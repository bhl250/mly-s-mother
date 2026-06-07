#!/usr/bin/python3
#-*- coding:utf-8 -*-

import os
import sys
import argparse
import logging
import copy
import xlrd
import json
import tqdm
import shutil
import pickle
import random
import binascii
import operator
import subprocess
import numpy as np
import pandas as pd
from functools import reduce
from flowcontainer.extractor import extract

try:
    from pcap_splitter.splitter import PcapSplitter
except ImportError:
    PcapSplitter = None

random.seed(40)

word_dir = os.environ.get("WORD_DIR", os.path.join(os.getcwd(), "corpora"))
word_name = "encrypted_burst.txt"
LOGGER = logging.getLogger("processdata")

def configure_logging(log_file=None, log_level="INFO"):
    level = getattr(logging, log_level.upper(), logging.INFO)
    handlers = [logging.StreamHandler()]
    if log_file:
        os.makedirs(os.path.dirname(os.path.abspath(log_file)), exist_ok=True)
        handlers.append(logging.FileHandler(log_file, mode="a"))
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=handlers,
        force=True,
    )

def _default_log_file(command):
    log_names = {
        "pretrain": "pretrain.log",
        "split-finetune": "finetune_split.log",
    }
    return os.path.join(os.getcwd(), "logs", log_names.get(command, "preprocess.log"))

def _run_tool(args):
    try:
        subprocess.run(args, check=True)
    except FileNotFoundError as exc:
        raise RuntimeError(
            "Required external tool not found: %s. On Ubuntu, install Wireshark CLI tools "
            "or PcapPlusPlus/pcap-splitter as needed." % args[0]
        ) from exc

def _pcap_output_name(pcap_name, suffix):
    base_name = os.path.splitext(os.path.basename(pcap_name))[0]
    safe_suffix = ''.join(char if char.isalnum() or char in ('-', '_') else '_' for char in suffix)
    return "%s_%s.pcap" % (base_name, safe_suffix)

def _rdpcap(path):
    from scapy.utils import rdpcap
    return rdpcap(path)

def _wrpcap(path, packets):
    from scapy.utils import PcapWriter, wrpcap
    try:
        return wrpcap(path, packets)
    except KeyError as exc:
        LOGGER.warning("Scapy could not infer pcap linktype for %s (%s); writing raw bytes with Ethernet linktype.", path, exc)
        writer = PcapWriter(path, linktype=1, sync=True)
        try:
            for packet in packets:
                sec = getattr(packet, "time", None)
                writer.write_packet(bytes(packet), sec=sec)
        finally:
            writer.close()

def _packet_session_key(packet, fallback_index):
    ip_layer = packet.getlayer("IP") or packet.getlayer("IPv6")
    if ip_layer is None:
        return ("other", fallback_index)

    transport = packet.getlayer("TCP") or packet.getlayer("UDP")
    proto = transport.name if transport is not None else str(ip_layer.proto)
    sport = getattr(transport, "sport", 0)
    dport = getattr(transport, "dport", 0)
    endpoint_a = (ip_layer.src, sport)
    endpoint_b = (ip_layer.dst, dport)
    return (proto,) + tuple(sorted([endpoint_a, endpoint_b]))

def _split_cap_with_scapy(pcap_file, output_path, pcap_name, dataset_level):
    packets = _rdpcap(pcap_file)
    if dataset_level == 'packet':
        for index, packet in enumerate(packets):
            target_file = os.path.join(output_path, _pcap_output_name(pcap_name, "packet_%06d" % index))
            _wrpcap(target_file, [packet])
        return

    sessions = {}
    for index, packet in enumerate(packets):
        sessions.setdefault(_packet_session_key(packet, index), []).append(packet)

    for index, packets_in_session in enumerate(sessions.values()):
        target_file = os.path.join(output_path, _pcap_output_name(pcap_name, "flow_%06d" % index))
        _wrpcap(target_file, packets_in_session)

def convert_pcapng_2_pcap(pcapng_path, pcapng_file, output_path):

    os.makedirs(output_path, exist_ok=True)
    source_file = os.path.join(pcapng_path, pcapng_file)
    pcap_file = os.path.join(output_path, os.path.basename(pcapng_file).replace('pcapng','pcap'))
    _run_tool(["editcap", "-F", "pcap", source_file, pcap_file])
    return 0

def split_cap(pcap_path, pcap_file, pcap_name, pcap_label='', dataset_level = 'flow'):

    splitcap_root = os.path.join(pcap_path, "splitcap")
    os.makedirs(splitcap_root, exist_ok=True)
    if pcap_label != '':
        output_path = os.path.join(splitcap_root, pcap_label, pcap_name)
    else:
        output_path = os.path.join(splitcap_root, pcap_name)
    os.makedirs(output_path, exist_ok=True)

    if dataset_level not in ('flow', 'packet'):
        raise ValueError("Unsupported dataset_level: %s" % dataset_level)

    try:
        if PcapSplitter is None:
            raise RuntimeError("pcap-splitter is not installed")
        if shutil.which("PcapSplitter") is None:
            raise RuntimeError("PcapSplitter executable is not installed or not in PATH")
        splitter = PcapSplitter(pcap_file)
        if dataset_level == 'flow':
            splitter.split_by_session(output_path)
        elif dataset_level == 'packet':
            splitter.split_by_count(1, output_path)
    except Exception as exc:
        LOGGER.warning("PcapSplitter is unavailable for %s (%s); falling back to Scapy splitting.", pcap_file, exc)
        _split_cap_with_scapy(pcap_file, output_path, pcap_name, dataset_level)
    LOGGER.info("Split finished: input=%s level=%s output=%s", pcap_file, dataset_level, output_path)
    return output_path

def cut(obj, sec):
    result = [obj[i:i+sec] for i in range(0,len(obj),sec)]
    try:
        remanent_count = len(result[0])%4
    except Exception as e:
        remanent_count = 0
        print("cut datagram error!")
    if remanent_count == 0:
        pass
    else:
        result = [obj[i:i+sec+remanent_count] for i in range(0,len(obj),sec+remanent_count)]
    return result

def bigram_generation(packet_datagram, packet_len = 64, flag=True):
    result = ''
    generated_datagram = cut(packet_datagram,1)
    token_count = 0
    for sub_string_index in range(len(generated_datagram)):
        if sub_string_index != (len(generated_datagram) - 1):
            token_count += 1
            if token_count > packet_len:
                break
            else:
                merge_word_bigram = generated_datagram[sub_string_index] + generated_datagram[sub_string_index + 1]
        else:
            break
        result += merge_word_bigram
        result += ' '
    
    return result

def get_burst_feature(label_pcap, payload_len):
    feature_data = []
    
    packets = _rdpcap(label_pcap)
    
    packet_direction = []
    feature_result = extract(label_pcap)
    for key in feature_result.keys():
        value = feature_result[key]
        packet_direction = [x // abs(x) for x in value.ip_lengths]

    if len(packet_direction) == len(packets):
        
        burst_data_string = ''
        
        burst_txt = ''
        
        for packet_index in range(len(packets)):
            packet_data = packets[packet_index].copy()
            data = (binascii.hexlify(bytes(packet_data)))
            
            packet_string = data.decode()[:2*payload_len]
            
            if packet_index == 0:
                burst_data_string += packet_string
            else:
                if packet_direction[packet_index] != packet_direction[packet_index - 1]:
                    
                    length = len(burst_data_string)
                    for string_txt in cut(burst_data_string, int(length / 2)):
                        burst_txt += bigram_generation(string_txt, packet_len=len(string_txt))
                        burst_txt += '\n'
                    burst_txt += '\n'
                    
                    burst_data_string = ''
                
                burst_data_string += packet_string
                if packet_index == len(packets) - 1:
                    
                    length = len(burst_data_string)
                    for string_txt in cut(burst_data_string, int(length / 2)):
                        burst_txt += bigram_generation(string_txt, packet_len=len(string_txt))
                        burst_txt += '\n'
                    burst_txt += '\n'
        
        os.makedirs(word_dir, exist_ok=True)
        with open(os.path.join(word_dir, word_name),'a') as f:
            f.write(burst_txt)
    return 0

def get_feature_packet(label_pcap,payload_len):
    feature_data = []

    packets = _rdpcap(label_pcap)
    packet_data_string = ''  

    for packet in packets:
            packet_data = packet.copy()
            data = (binascii.hexlify(bytes(packet_data)))
            packet_string = data.decode()
            new_packet_string = packet_string[76:]
            packet_data_string += bigram_generation(new_packet_string, packet_len=payload_len, flag = True)
            break

    feature_data.append(packet_data_string)
    return feature_data

def get_feature_flow(label_pcap, payload_len, payload_pac):
    
    feature_data = []
    packets = _rdpcap(label_pcap)
    packet_count = 0  
    flow_data_string = '' 

    feature_result = extract(label_pcap, filter='tcp', extension=['tls.record.content_type', 'tls.record.opaque_type', 'tls.handshake.type'])
    if len(feature_result) == 0:
        feature_result = extract(label_pcap, filter='udp')
        if len(feature_result) == 0:
            return -1
        extract_keys = list(feature_result.keys())[0]
        if len(feature_result[label_pcap, extract_keys[1], extract_keys[2]].ip_lengths) < 3:
            print("preprocess flow %s but this flow has less than 3 packets." % label_pcap)
            return -1
    elif len(packets) < 3:
        print("preprocess flow %s but this flow has less than 3 packets." % label_pcap)
        return -1
    try:
        if len(feature_result[label_pcap, 'tcp', '0'].ip_lengths) < 3:
            print("preprocess flow %s but this flow has less than 3 packets." % label_pcap)
            return -1
    except Exception as e:
        print("*** this flow begings from 1 or other numbers than 0.")
        for key in feature_result.keys():
            if len(feature_result[key].ip_lengths) < 3:
                print("preprocess flow %s but this flow has less than 3 packets." % label_pcap)
                return -1

    if feature_result.keys() == {}.keys():
        return -1
    
    if feature_result == {}:
        return -1
    feature_result_lens = len(feature_result.keys())
    for key in feature_result.keys():
        value = feature_result[key]

    packet_index = 0
    for packet in packets:
        packet_count += 1
        if packet_count == payload_pac:
            packet_data = packet.copy()
            data = (binascii.hexlify(bytes(packet_data)))
            packet_string = data.decode()[76:]
            flow_data_string += bigram_generation(packet_string, packet_len=payload_len, flag = True)
            break
        else:
            packet_data = packet.copy()
            data = (binascii.hexlify(bytes(packet_data)))
            packet_string = data.decode()[76:]
            flow_data_string += bigram_generation(packet_string, packet_len=payload_len, flag = True)
    feature_data.append(flow_data_string)

    return feature_data

def generation(pcap_path, samples, features, splitcap = False, payload_length = 128, payload_packet = 5, dataset_save_path = None, dataset_level = "flow"):
    dataset_save_path = dataset_save_path or os.environ.get("DATASET_SAVE_PATH", os.path.join(os.getcwd(), "ex_results"))
    dataset_json_path = os.path.join(dataset_save_path, "dataset.json")
    if os.path.exists(dataset_json_path):
        print("the pcap file of %s is finished generating."%pcap_path)
        
        clean_dataset = 0
        
        re_write = 0

        if clean_dataset:
            with open(dataset_json_path, "r") as f:
                new_dataset = json.load(f)
            pop_keys = ['1','10','16','23','25','71']
            print("delete domains.")
            for p_k in pop_keys:
                print(new_dataset.pop(p_k))
            
            change_keys = [str(x) for x in range(113, 119)]
            relation_dict = {}
            for c_k_index in range(len(change_keys)):
                relation_dict[change_keys[c_k_index]] = pop_keys[c_k_index]
                new_dataset[pop_keys[c_k_index]] = new_dataset.pop(change_keys[c_k_index])
            with open(dataset_json_path, "w") as f:
                json.dump(new_dataset, fp=f, ensure_ascii=False, indent=4)
        elif re_write:
            with open(dataset_json_path, "r") as f:
                old_dataset = json.load(f)
            os.renames(dataset_json_path, os.path.join(dataset_save_path, "old_dataset.json"))
            with open(os.path.join(dataset_save_path, "new-samples.txt"), "r") as f:
                source_samples = f.read().split('\n')
            new_dataset = {}
            samples_count = 0
            for i in range(len(source_samples)):
                current_class = source_samples[i].split('\t')
                if int(current_class[1]) > 9:
                    new_dataset[str(samples_count)] = old_dataset[str(i)]
                    samples_count += 1
                    print(old_dataset[str(i)]['samples'])
            with open(dataset_json_path, "w") as f:
                json.dump(new_dataset, fp=f, ensure_ascii=False, indent=4)
        X, Y = obtain_data(pcap_path, samples, features, dataset_save_path)
        return X,Y

    dataset = {}
    
    label_name_list = []

    session_pcap_path  = {}

    for parent, dirs, files in os.walk(pcap_path):
        if label_name_list == []:
            label_name_list.extend(dirs)

        tls13 = 0
        if tls13:
            record_file = os.environ.get("PICKED_FILE_RECORD", os.path.join(os.getcwd(), "ex_results", "picked_file_record"))
            target_path = os.environ.get("PACKET_SPLITCAP_PATH", os.path.join(os.getcwd(), "ex_results", "packet_splitcap"))
            if not os.path.getsize(target_path):
                with open(record_file, 'r') as f:
                    record_files = f.read().split('\n')
                for file in record_files[:-2]:
                    file_parts = file.replace("\\", os.sep).split(os.sep)
                    current_path = os.path.join(target_path, file_parts[5])
                    new_name = '_'.join(file_parts[6:])
                    if not os.path.exists(current_path):
                        os.mkdir(current_path)
                    shutil.copyfile(file, os.path.join(current_path, new_name))

        for dir in label_name_list:
            for p,dd,ff in os.walk(os.path.join(parent, dir)):
                
                if splitcap:
                    for file in ff:
                        session_path = (split_cap(pcap_path, os.path.join(p, file), file.split(".")[-2], dir, dataset_level = dataset_level))
                    session_pcap_path[dir] = os.path.join(pcap_path, "splitcap", dir)
                else:
                    session_pcap_path[dir] = os.path.join(pcap_path, dir)
        break

    label_id = {}
    for index in range(len(label_name_list)):
        label_id[label_name_list[index]] = index

    r_file_record = []
    print("\nBegin to generate features.")

    label_count = 0
    for key in tqdm.tqdm(session_pcap_path.keys()):

        if dataset_level == "flow":
            if splitcap:
                for p, d, f in os.walk(session_pcap_path[key]):
                    for file in f:
                        current_file = os.path.join(p, file)
                        file_size = float(size_format(os.path.getsize(current_file)))
                        # 2KB
                        if file_size < 5:
                            os.remove(current_file)
                            print("remove sample: %s for its size is less than 5 KB." % current_file)

            if label_id[key] not in dataset:
                dataset[label_id[key]] = {
                    "samples": 0,
                    "payload": {},
                    "length": {},
                    "time": {},
                    "direction": {},
                    "message_type": {}
                }
        elif dataset_level == "packet":
            if splitcap:# not splitcap
                for p, d, f in os.walk(session_pcap_path[key]):
                    for file in f:
                        current_file = os.path.join(p, file)
                        if not os.path.getsize(current_file):
                            os.remove(current_file)
                            print("current pcap %s is 0KB and delete"%current_file)
                        else:
                            current_packet = _rdpcap(current_file)
                            file_size = float(size_format(os.path.getsize(current_file)))
                            try:
                                if 'TCP' in str(current_packet.res):
                                    # 0.12KB
                                    if file_size < 0.14:
                                        os.remove(current_file)
                                        print("remove TCP sample: %s for its size is less than 0.14KB." % (
                                                    current_file))
                                elif 'UDP' in str(current_packet.res):
                                    if file_size < 0.1:
                                        os.remove(current_file)
                                        print("remove UDP sample: %s for its size is less than 0.1KB." % (
                                                    current_file))
                            except Exception as e:
                                print("error in data_generation 611: scapy read pcap and analyse error")
                                os.remove(current_file)
                                print("remove packet sample: %s for reading error." % current_file)
            if label_id[key] not in dataset:
                dataset[label_id[key]] = {
                    "samples": 0,
                    "payload": {}
                }
        if splitcap:
            continue

        target_all_files = [os.path.join(x[0], y) for x in [(p, f) for p, d, f in os.walk(session_pcap_path[key])] for y in x[1]]
        r_files = random.sample(target_all_files, samples[label_count])
        label_count += 1
        for r_f in r_files:
            if dataset_level == "flow":
                feature_data = get_feature_flow(r_f, payload_len=payload_length, payload_pac=payload_packet)
            elif dataset_level == "packet":
                feature_data = get_feature_packet(r_f, payload_len=payload_length)

            if feature_data == -1:
                continue
            r_file_record.append(r_f)
            dataset[label_id[key]]["samples"] += 1
            if len(dataset[label_id[key]]["payload"].keys()) > 0:
                dataset[label_id[key]]["payload"][str(dataset[label_id[key]]["samples"])] = \
                    feature_data[0]
                if dataset_level == "flow":
                    pass
            else:
                dataset[label_id[key]]["payload"]["1"] = feature_data[0]
                if dataset_level == "flow":
                    pass

    all_data_number = 0
    for index in range(len(label_name_list)):
        print("%s\t%s\t%d"%(label_id[label_name_list[index]], label_name_list[index], dataset[label_id[label_name_list[index]]]["samples"]))
        all_data_number += dataset[label_id[label_name_list[index]]]["samples"]
    print("all\t%d"%(all_data_number))

    os.makedirs(dataset_save_path, exist_ok=True)
    with open(os.path.join(dataset_save_path, "picked_file_record"),"w") as p_f:
        for i in r_file_record:
            p_f.write(i)
            p_f.write("\n")
    with open(dataset_json_path, "w") as f:
        json.dump(dataset,fp=f,ensure_ascii=False,indent=4)

    X,Y = obtain_data(pcap_path, samples, features, dataset_save_path, json_data = dataset)
    return X,Y

def read_data_from_json(json_data, features, samples):
    X,Y = [], []
    ablation_flag = 0
    for feature_index in range(len(features)):
        x = []
        label_count = 0
        for label in json_data.keys():
            sample_num = json_data[label]["samples"]
            if X == []:
                if not ablation_flag:
                    y = [label] * sample_num
                    Y.append(y)
                else:
                    if sample_num > 1500:
                        y = [label] * 1500
                    else:
                        y = [label] * sample_num
                    Y.append(y)
            if samples[label_count] < sample_num:
                x_label = []
                for sample_index in random.sample(list(json_data[label][features[feature_index]].keys()),1500):
                    x_label.append(json_data[label][features[feature_index]][sample_index])
                x.append(x_label)
            else:
                x_label = []
                for sample_index in json_data[label][features[feature_index]].keys():
                    x_label.append(json_data[label][features[feature_index]][sample_index])
                x.append(x_label)
            label_count += 1
        X.append(x)
    return X,Y

def obtain_data(pcap_path, samples, features, dataset_save_path, json_data = None):
    
    if json_data:
        X,Y = read_data_from_json(json_data,features,samples)
    else:
        print("read dataset from json file.")
        with open(os.path.join(dataset_save_path, "dataset.json"),"r") as f:
            dataset = json.load(f)
        X,Y = read_data_from_json(dataset,features,samples)

    for index in range(len(X)):
        if len(X[index]) != len(Y):
            print("data and labels are not properly associated.")
            print("x:%s\ty:%s"%(len(X[index]),len(Y)))
            return -1
    return X,Y

def combine_dataset_json(dataset_name=None, output_file=None):
    dataset_name = dataset_name or os.environ.get("DATASET_JSON_PREFIX", os.path.join(os.getcwd(), "traffic_pcap", "splitcap", "dataset-"))
    output_file = output_file or os.environ.get("DATASET_JSON_OUTPUT", os.path.join(os.getcwd(), "traffic_pcap", "splitcap", "dataset.json"))
    # dataset vocab
    dataset = {}
    # progress
    progress_num = 8
    for i in range(progress_num):
        dataset_file = dataset_name + str(i) + ".json"
        with open(dataset_file,"r") as f:
            json_data = json.load(f)
        for key in json_data.keys():
            if i > 1:
                new_key = int(key) + 9*1 + 6*(i-1)
            else:
                new_key = int(key) + 9*i
            print(new_key)
            if new_key not in dataset.keys():
                dataset[new_key] = json_data[key]
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file,"w") as f:
        json.dump(dataset, fp=f, ensure_ascii=False, indent=4)
    return 0

def pretrain_dataset_generation(pcap_path, output_split_path=None, pcap_output_path=None, payload_len=64, force=False):
    if not os.path.isdir(pcap_path):
        raise FileNotFoundError("Input --pcap-path does not exist or is not a directory: %s" % pcap_path)
    output_split_path = output_split_path or os.environ.get("OUTPUT_SPLIT_PATH", os.path.join(os.getcwd(), "dataset"))
    pcap_output_path = pcap_output_path or os.environ.get("PCAP_OUTPUT_PATH", os.path.join(output_split_path, "pcap"))
    os.makedirs(output_split_path, exist_ok=True)
    os.makedirs(pcap_output_path, exist_ok=True)
    splitcap_path = os.path.join(output_split_path, "splitcap")
    word_path = os.path.join(word_dir, word_name)
    if force:
        if os.path.exists(splitcap_path):
            LOGGER.info("Force enabled: removing existing splitcap directory: %s", splitcap_path)
            shutil.rmtree(splitcap_path)
        if os.path.exists(word_path):
            LOGGER.info("Force enabled: removing existing pretrain corpus: %s", word_path)
            os.remove(word_path)
    LOGGER.info("Pretrain started: pcap_path=%s output_split_path=%s pcap_output_path=%s word_dir=%s word_name=%s payload_len=%s",
                pcap_path, output_split_path, pcap_output_path, word_dir, word_name, payload_len)
    
    if not os.listdir(pcap_output_path):
        raw_files = [
            (parent, file)
            for parent, dirs, files in os.walk(pcap_path)
            for file in files
            if file.endswith((".pcap", ".pcapng"))
        ]
        LOGGER.info("Normalize pcaps: total=%d", len(raw_files))
        converted_count = 0
        copied_count = 0
        for _parent, file in tqdm.tqdm(raw_files, desc="normalize-pcaps"):
            if file.endswith(".pcapng"):
                convert_pcapng_2_pcap(_parent, file, pcap_output_path)
                converted_count += 1
            else:
                shutil.copy(os.path.join(_parent, file), os.path.join(pcap_output_path, file))
                copied_count += 1
        LOGGER.info("Normalize pcaps finished: total=%d converted=%d copied=%d output=%s",
                    len(raw_files), converted_count, copied_count, pcap_output_path)
    else:
        LOGGER.info("Skip normalization because pcap_output_path is not empty: %s", pcap_output_path)
    
    if not os.path.exists(splitcap_path):
        split_inputs = [
            os.path.join(parent, file)
            for parent, dirs, files in os.walk(pcap_output_path)
            for file in files
            if file.endswith(".pcap")
        ]
        LOGGER.info("Split pretrain pcaps as session flows: total=%d", len(split_inputs))
        for file_path in tqdm.tqdm(split_inputs, desc="split-pretrain"):
            split_cap(output_split_path, file_path, os.path.basename(file_path))
        LOGGER.info("Split pretrain pcaps finished: total=%d output=%s", len(split_inputs), splitcap_path)
    else:
        LOGGER.info("Skip splitting because splitcap directory already exists: %s", splitcap_path)

    burst_inputs = [
        os.path.join(parent, file)
        for parent, dirs, files in os.walk(splitcap_path)
        for file in files
        if file.endswith(".pcap")
    ]
    LOGGER.info("Generate burst dataset: total_split_pcaps=%d", len(burst_inputs))
    for file_path in tqdm.tqdm(burst_inputs, desc="burst-features"):
        get_burst_feature(file_path, payload_len=payload_len)
    LOGGER.info("Pretrain finished: burst_inputs=%d output_file=%s", len(burst_inputs), os.path.join(word_dir, word_name))
    return 0

def split_finetune_pcaps(pcap_path, dataset_level='packet', force=False):
    if not os.path.isdir(pcap_path):
        raise FileNotFoundError("Input --pcap-path does not exist or is not a directory: %s" % pcap_path)
    labels = [
        label for label in os.listdir(pcap_path)
        if os.path.isdir(os.path.join(pcap_path, label)) and label != "splitcap"
    ]
    splitcap_path = os.path.join(pcap_path, "splitcap")
    if force and os.path.exists(splitcap_path):
        LOGGER.info("Force enabled: removing existing splitcap directory: %s", splitcap_path)
        shutil.rmtree(splitcap_path)
    LOGGER.info("Fine-tune split started: pcap_path=%s dataset_level=%s labels=%d", pcap_path, dataset_level, len(labels))
    total_files = 0
    total_converted = 0
    for label in tqdm.tqdm(labels, desc="labels"):
        label_dir = os.path.join(pcap_path, label)
        label_files = [
            (parent, file)
            for parent, dirs, files in os.walk(label_dir)
            for file in files
            if file.endswith((".pcap", ".pcapng"))
        ]
        LOGGER.info("Split label started: label=%s files=%d", label, len(label_files))
        for parent, dirs, files in os.walk(label_dir):
            for file in files:
                if not file.endswith((".pcap", ".pcapng")):
                    continue
                pcap_file = os.path.join(parent, file)
                pcap_name = os.path.splitext(file)[0]
                if file.endswith(".pcapng"):
                    converted_dir = os.path.join(pcap_path, "converted_pcap", label)
                    convert_pcapng_2_pcap(parent, file, converted_dir)
                    pcap_file = os.path.join(converted_dir, file.replace("pcapng", "pcap"))
                    pcap_name = os.path.splitext(os.path.basename(pcap_file))[0]
                    total_converted += 1
                split_cap(pcap_path, pcap_file, pcap_name, label, dataset_level=dataset_level)
                total_files += 1
        LOGGER.info("Split label finished: label=%s files=%d", label, len(label_files))
    LOGGER.info("Fine-tune split finished: labels=%d files=%d converted_pcapng=%d output=%s",
                len(labels), total_files, total_converted, splitcap_path)
    return splitcap_path

def size_format(size):
    # 'KB'
    file_size = '%.3f' % float(size/1000)
    return file_size

def _build_arg_parser():
    parser = argparse.ArgumentParser(
        description="PCAP preprocessing helpers for pre-training and fine-tuning data.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    default_pcap_path = os.environ.get("PCAP_PATH")

    pretrain_parser = subparsers.add_parser(
        "pretrain",
        help="Generate BURST corpus for pre-training.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    pretrain_parser.add_argument("--pcap-path", default=default_pcap_path, required=default_pcap_path is None,
                                 help="Required raw pcap/pcapng input directory. Can also be provided with PCAP_PATH.")
    pretrain_parser.add_argument("--output-split-path", default=os.environ.get("OUTPUT_SPLIT_PATH", os.path.join(os.getcwd(), "dataset")),
                                 help="Directory where split session pcaps are written.")
    pretrain_parser.add_argument("--pcap-output-path", default=argparse.SUPPRESS,
                                 help="Directory where normalized .pcap files are written. Defaults to OUTPUT_SPLIT_PATH/pcap.")
    pretrain_parser.add_argument("--word-dir", default=os.environ.get("WORD_DIR", os.path.join(os.getcwd(), "corpora")),
                                 help="Directory for the generated pre-training corpus text file.")
    pretrain_parser.add_argument("--word-name", default=os.environ.get("WORD_NAME", word_name),
                                 help="Generated pre-training corpus filename.")
    pretrain_parser.add_argument("--payload-len", type=int, default=64,
                                 help="Payload length used by BURST feature extraction.")
    pretrain_parser.add_argument("--log-file", default=argparse.SUPPRESS,
                                 help="Log file path. Defaults to ./logs/pretrain.log.")
    pretrain_parser.add_argument("--log-level", default=os.environ.get("LOG_LEVEL", "INFO"),
                                 help="Logging level.")
    pretrain_parser.add_argument("--force", action="store_true",
                                 help="Remove existing splitcap output and pretrain corpus before running.")

    split_parser = subparsers.add_parser(
        "split-finetune",
        help="Split labeled fine-tuning pcaps into packet/session pcaps.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    split_parser.add_argument("--pcap-path", default=default_pcap_path, required=default_pcap_path is None,
                              help="Required labeled raw pcap root. Expected layout: PCAP_PATH/<label>/*.pcap. Can also be provided with PCAP_PATH.")
    split_parser.add_argument("--dataset-level", choices=["packet", "flow"], default="packet",
                              help="Use packet to split each pcap into single-packet samples, or flow for session samples.")
    split_parser.add_argument("--log-file", default=argparse.SUPPRESS,
                              help="Log file path. Defaults to ./logs/finetune_split.log.")
    split_parser.add_argument("--log-level", default=os.environ.get("LOG_LEVEL", "INFO"),
                              help="Logging level.")
    split_parser.add_argument("--force", action="store_true",
                              help="Remove existing splitcap output before running.")

    return parser

if __name__ == '__main__':
    args = _build_arg_parser().parse_args()
    args.log_file = getattr(args, "log_file", os.environ.get("LOG_FILE")) or _default_log_file(args.command)
    configure_logging(args.log_file, args.log_level)
    if args.command == "pretrain":
        word_dir = args.word_dir
        word_name = args.word_name
        pretrain_dataset_generation(
            args.pcap_path,
            output_split_path=args.output_split_path,
            pcap_output_path=getattr(args, "pcap_output_path", None),
            payload_len=args.payload_len,
            force=args.force,
        )
    elif args.command == "split-finetune":
        output_path = split_finetune_pcaps(args.pcap_path, dataset_level=args.dataset_level, force=args.force)
        print("Fine-tuning split pcaps saved to: %s" % output_path)

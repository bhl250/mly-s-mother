#!/usr/bin/python3
#-*- coding:utf-8 -*-

import os
import shutil
import subprocess

def _run_tool(args):
    try:
        subprocess.run(args, check=True)
    except FileNotFoundError as exc:
        raise RuntimeError(
            "Required external tool not found: %s. On Ubuntu, install Wireshark CLI tools." % args[0]
        ) from exc

def fix_dataset(method, dataset_path=None, output_dir=None, source_root=None):
    dataset_path = dataset_path or os.environ.get("FIX_DATASET_PATH", os.path.join(os.getcwd(), "dataset", "cstnet-tls1.3"))
    output_dir = output_dir or os.environ.get("FIX_DATASET_OUTPUT", os.path.join(os.getcwd(), "dataset"))
    source_root = source_root or os.environ.get("FIX_DATASET_SOURCE_ROOT", os.getcwd())

    os.makedirs(output_dir, exist_ok=True)
    for p, d, f in os.walk(dataset_path):
        for label in d:
            if label != "0_merge_datas":
                label_domain = label.split(".")[0]
                source_dir = os.path.join(source_root, label)
                if not os.path.isdir(source_dir):
                    continue
                source_files = [
                    os.path.join(source_dir, file)
                    for file in os.listdir(source_dir)
                    if file.endswith(".pcap")
                ]
                if source_files:
                    _run_tool(["mergecap", "-w", os.path.join(output_dir, "%s.pcap" % label_domain)] + source_files)

    return 0

def reverse_dir2file(path=None):
    path = path or os.environ.get("DATASET_PATH", os.path.join(os.getcwd(), "dataset"))
    for p, d, f in os.walk(path):
        for file in f:
            shutil.move(os.path.join(p, file), path)
    return 0

def dataset_file2dir(file_path):
    for parent,dirs,files in os.walk(file_path):
        for file in files:
            label_name = file.split(".pcap")[0]
            label_dir = os.path.join(parent, label_name)
            os.mkdir(label_dir)
            shutil.move(os.path.join(parent, file), label_dir)
    return 0

def file_2_pcap(source_file,target_file):
    _run_tool(["tshark", "-F", "pcap", "-r", source_file, "-w", target_file])
    return 0

def clean_pcap(source_file):
    target_file = source_file.replace('.pcap','_clean.pcap')
    clean_protocols = "not arp and not dns and not stun and not dhcpv6 and not icmpv6 and not icmp and not dhcp and not llmnr and not nbns and not ntp and not igmp and frame.len > 80"
    _run_tool(["tshark", "-F", "pcap", "-r", source_file, "-Y", clean_protocols, "-w", target_file])
    return 0

def statistic_dataset_sample_count(data_path):
    dataset_label = []
    dataset_lengths = []

    tls13_flag = 1
    
    temp = []
    for p,d,f in os.walk(data_path):
        if p == data_path:
            dataset_label.extend(d)
        elif f == []:
            
            if (os.path.basename(p) not in dataset_label):
                continue

            file_num = 0
            for pp, dd, ff in os.walk(p):
                file_num += len(ff)
            dataset_lengths.extend([file_num])
            temp.append(p)
        else:
            if tls13_flag == 1:
                if (os.path.basename(p) not in dataset_label):
                    continue

                file_num = 0
                for pp, dd, ff in os.walk(p):
                    file_num += len(ff)
                dataset_lengths.extend([file_num])
                temp.append(p)
       
    print("label samples: ",dataset_lengths)
    print("labels: ",dataset_label)
    return dataset_lengths,dataset_label

if __name__ == '__main__':
    fix_dataset(['method'])

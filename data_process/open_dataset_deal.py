#!/usr/bin/python3
#-*- coding:utf-8 -*-

import os
import shutil
import subprocess
import re

PCAP_EXTENSIONS = (".pcap", ".pcapng")

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

def _pcap_files_under(path):
    return [
        os.path.join(parent, file)
        for parent, dirs, files in os.walk(path)
        for file in files
        if file.lower().endswith(PCAP_EXTENSIONS)
    ]

def is_labeled_pcap_root(path):
    if not os.path.isdir(path):
        return False
    for name in os.listdir(path):
        label_dir = os.path.join(path, name)
        if name in ("splitcap", "converted_pcap") or not os.path.isdir(label_dir):
            continue
        if _pcap_files_under(label_dir):
            return True
    return False

def infer_label_from_filename(file_name):
    stem = os.path.splitext(os.path.basename(file_name))[0]

    split_suffix = re.search(r"(.+?)[_-](?:packet|flow|session)[_-]?\d+$", stem, re.IGNORECASE)
    if split_suffix:
        stem = split_suffix.group(1)

    label_match = re.match(r"^(label[_-]?\d+)(?:[_\-.].*)?$", stem, re.IGNORECASE)
    if label_match:
        return label_match.group(1)

    number_match = re.match(r"^(\d+)(?:[_\-.].*)?$", stem)
    if number_match:
        return number_match.group(1)

    token_match = re.match(r"^(.+?)(?:[_\-.]\d+|[_\-.](?:packet|flow|session)[_\-.]?\d+|$)", stem, re.IGNORECASE)
    if token_match:
        return token_match.group(1).strip("_-.")

    return stem.strip("_-.")

def _unique_target_path(target_dir, file_name):
    target_file = os.path.join(target_dir, file_name)
    if not os.path.exists(target_file):
        return target_file

    stem, ext = os.path.splitext(file_name)
    count = 1
    while True:
        target_file = os.path.join(target_dir, "%s_%d%s" % (stem, count, ext))
        if not os.path.exists(target_file):
            return target_file
        count += 1

def _safe_symlink(source_file, target_file):
    if os.path.lexists(target_file):
        if os.path.islink(target_file):
            existing_target = os.readlink(target_file)
            if os.path.abspath(os.path.join(os.path.dirname(target_file), existing_target)) == os.path.abspath(source_file):
                return
        os.unlink(target_file)
    os.symlink(source_file, target_file)

def classify_flat_pcap_root(path, output_path=None, copy_files=False):
    if is_labeled_pcap_root(path):
        return path, {}

    pcap_files = _pcap_files_under(path)
    if not pcap_files:
        return path, {}

    source_parent = os.path.dirname(os.path.abspath(path))
    source_name = os.path.basename(os.path.abspath(path))
    output_path = output_path or os.path.join(source_parent, "%s_classified" % source_name)
    os.makedirs(output_path, exist_ok=True)

    label_counts = {}
    target_paths = set()
    for source_file in pcap_files:
        if os.path.abspath(source_file).startswith(os.path.abspath(output_path) + os.sep):
            continue
        label = infer_label_from_filename(source_file)
        if not label:
            continue
        target_dir = os.path.join(output_path, label)
        os.makedirs(target_dir, exist_ok=True)
        target_file = os.path.join(target_dir, os.path.basename(source_file))
        if target_file in target_paths:
            target_file = _unique_target_path(target_dir, os.path.basename(source_file))
        target_paths.add(target_file)
        if copy_files:
            shutil.copy2(source_file, target_file)
        else:
            _safe_symlink(source_file, target_file)
        label_counts[label] = label_counts.get(label, 0) + 1

    return output_path, label_counts

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

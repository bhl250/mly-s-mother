#!/usr/bin/python3
#-*- coding:utf-8 -*-

import numpy as np
import argparse
import logging
import json
import os
import time
import xlrd
import pickle
from sklearn.model_selection import StratifiedShuffleSplit
import pandas as pd
from scipy.stats import skew,kurtosis
import sys
import csv
import copy
import tqdm
import random
import shutil
import dataset_generation

import data_preprocess
import open_dataset_deal

_category = 120 # dataset class
dataset_dir = os.environ.get("DATASET_DIR", os.path.join(os.getcwd(), "datasets")) # the path to save dataset for dine-tuning

pcap_path = os.environ.get("PCAP_PATH")
dataset_save_path = os.environ.get("DATASET_SAVE_PATH", os.path.join(os.getcwd(), "finetune_result"))
samples, features, dataset_level = [5000], ["payload"], "packet"
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

def _default_log_file():
    return os.path.join(os.getcwd(), "logs", "finetune_generate.log")

def _parse_csv_ints(value):
    return [int(item.strip()) for item in value.split(",") if item.strip()]

def _parse_csv_strings(value):
    return [item.strip() for item in value.split(",") if item.strip()]

def dataset_extract(model):
    
    X_dataset = {}
    Y_dataset = {}
    LOGGER.info("Fine-tune generation started: pcap_path=%s dataset_save_path=%s dataset_dir=%s samples=%s features=%s dataset_level=%s models=%s category=%s",
                pcap_path, dataset_save_path, dataset_dir, samples[:10], features, dataset_level, model, _category)

    try:
        dataset_cache_dir = os.path.join(dataset_save_path, "dataset")
        if os.listdir(dataset_cache_dir):
            LOGGER.info("Reading cached dataset arrays from %s", dataset_cache_dir)
            
            x_payload_train, x_payload_test, x_payload_valid,\
            y_train, y_test, y_valid = \
                np.load(os.path.join(dataset_cache_dir, "x_datagram_train.npy"),allow_pickle=True), np.load(os.path.join(dataset_cache_dir, "x_datagram_test.npy"),allow_pickle=True), np.load(os.path.join(dataset_cache_dir, "x_datagram_valid.npy"),allow_pickle=True),\
                np.load(os.path.join(dataset_cache_dir, "y_train.npy"),allow_pickle=True), np.load(os.path.join(dataset_cache_dir, "y_test.npy"),allow_pickle=True), np.load(os.path.join(dataset_cache_dir, "y_valid.npy"),allow_pickle=True)
            
            X_dataset, Y_dataset = models_deal(model, X_dataset, Y_dataset,
                                               x_payload_train, x_payload_test,
                                               x_payload_valid,
                                               y_train, y_test, y_valid)

            return X_dataset, Y_dataset
    except Exception as e:
        LOGGER.info("Dataset cache not available: %s", e)
        LOGGER.info("Begin to obtain new dataset: %s", os.path.join(dataset_save_path, "dataset"))

    X,Y = dataset_generation.generation(pcap_path, samples, features, splitcap=False, dataset_save_path=dataset_save_path,dataset_level=dataset_level)

    dataset_statistic = [0] * _category

    X_payload= []
    Y_all = []
    for app_label in Y:
        for label in app_label:
            Y_all.append(int(label))
    for label_id in range(_category):
        for label in Y_all:
            if label == label_id:
                dataset_statistic[label_id] += 1
    print("category flow")
    for index in range(len(dataset_statistic)):
        print("%s\t%d" % (index, dataset_statistic[index]))
    print("all\t%d" % (sum(dataset_statistic)))
    LOGGER.info("Dataset statistics: total=%d non_empty_categories=%d first_20=%s",
                sum(dataset_statistic), len([count for count in dataset_statistic if count > 0]), dataset_statistic[:20])

    for i in range(len(features)):
        if features[i] == "payload":
            for index_label in range(len(X[0])):
                for index_sample in range(len(X[0][index_label])):
                    X_payload.append(X[0][index_label][index_sample])

    split_1 = StratifiedShuffleSplit(n_splits=1, test_size=0.2, random_state=41) 
    split_2 = StratifiedShuffleSplit(n_splits=1, test_size=0.5, random_state=42) 

    x_payload = np.array(X_payload)
    dataset_label = np.array(Y_all)

    x_payload_train = []
    y_train = []

    x_payload_valid = []
    y_valid = []

    x_payload_test = []
    y_test = []

    for train_index, test_index in split_1.split(x_payload, dataset_label):
        x_payload_train, y_train = x_payload[train_index], dataset_label[train_index]
        x_payload_test, y_test = x_payload[test_index], dataset_label[test_index]
    for test_index, valid_index in split_2.split(x_payload_test, y_test):
        x_payload_valid, y_valid = x_payload_test[valid_index], y_test[valid_index]
        x_payload_test, y_test = x_payload_test[test_index], y_test[test_index]

    dataset_cache_dir = os.path.join(dataset_save_path, "dataset")
    if not os.path.exists(dataset_cache_dir):
        os.makedirs(dataset_cache_dir)

    output_x_payload_train = os.path.join(dataset_cache_dir, 'x_datagram_train.npy')

    output_x_payload_test = os.path.join(dataset_cache_dir, 'x_datagram_test.npy')

    output_x_payload_valid = os.path.join(dataset_cache_dir, 'x_datagram_valid.npy')

    output_y_train = os.path.join(dataset_cache_dir,'y_train.npy')
    output_y_test = os.path.join(dataset_cache_dir, 'y_test.npy')
    output_y_valid = os.path.join(dataset_cache_dir, 'y_valid.npy')

    np.save(output_x_payload_train, x_payload_train)
    np.save(output_x_payload_test, x_payload_test)
    np.save(output_x_payload_valid, x_payload_valid)

    np.save(output_y_train, y_train)
    np.save(output_y_test, y_test)
    np.save(output_y_valid, y_valid)
    LOGGER.info("Saved numpy datasets: train=%d valid=%d test=%d output_dir=%s",
                len(y_train), len(y_valid), len(y_test), dataset_cache_dir)

    X_dataset, Y_dataset = models_deal(model, X_dataset, Y_dataset,
                                       x_payload_train, x_payload_test, x_payload_valid,
                                       y_train, y_test, y_valid)

    return X_dataset,Y_dataset

def models_deal(model, X_dataset, Y_dataset, x_payload_train, x_payload_test, x_payload_valid, y_train, y_test, y_valid):
    for index in range(len(model)):
        print("Begin to model %s dealing..."%model[index])
        x_train_dataset = []
        x_test_dataset = []
        x_valid_dataset = []

        if model[index] == "pre-train":
            save_dir = dataset_dir
            write_dataset_tsv(x_payload_train, y_train, save_dir, "train")
            write_dataset_tsv(x_payload_test, y_test, save_dir, "test")
            write_dataset_tsv(x_payload_valid, y_valid, save_dir, "valid")
            LOGGER.info("Saved TSV datasets: train=%d test=%d valid=%d output_dir=%s",
                        len(y_train), len(y_test), len(y_valid), save_dir)
            print("finish generating pre-train's datagram dataset.\nPlease check in %s" % save_dir)
            unlabel_data(os.path.join(dataset_dir, "test_dataset.tsv"))

        X_dataset[model[index]] = {"train": [], "valid": [], "test": []}
        Y_dataset[model[index]] = {"train": [], "valid": [], "test": []}

        X_dataset[model[index]]["train"], Y_dataset[model[index]]["train"] = x_train_dataset, y_train
        X_dataset[model[index]]["valid"], Y_dataset[model[index]]["valid"] = x_valid_dataset, y_valid
        X_dataset[model[index]]["test"], Y_dataset[model[index]]["test"] = x_test_dataset, y_test

    return X_dataset, Y_dataset

def write_dataset_tsv(data,label,file_dir,type):
    os.makedirs(file_dir, exist_ok=True)
    dataset_file = [["label", "text_a"]]
    for index in range(len(label)):
        dataset_file.append([label[index], data[index]])
    with open(os.path.join(file_dir, type + "_dataset.tsv"), 'w',newline='') as f:
        tsv_w = csv.writer(f, delimiter='\t')
        tsv_w.writerows(dataset_file)
    return 0

def unlabel_data(label_data):
    nolabel_data = ""
    with open(label_data,newline='') as f:
        data = csv.reader(f,delimiter='\t')
        for row in data:
            nolabel_data += row[1] + '\n'
    nolabel_file = label_data.replace("test_dataset","nolabel_test_dataset")
    #nolabel_file = label_data.replace("train_dataset", "nolabel_train_dataset")
    with open(nolabel_file, 'w',newline='') as f:
        f.write(nolabel_data)
    return 0

def cut_byte(obj, sec):
    result = [obj[i:i+sec] for i in range(0,len(obj),sec)]
    remanent_count = len(result[0])%2
    if remanent_count == 0:
        pass
    else:
        result = [obj[i:i+sec+remanent_count] for i in range(0,len(obj),sec+remanent_count)]
    return result

def pickle_save_data(path_file, data):
    with open(path_file, "wb") as f:
        pickle.dump(data, f)
    return 0

def count_label_number(samples):
    new_samples = samples * _category
    
    if 'splitcap' not in pcap_path:
        dataset_length, labels = open_dataset_deal.statistic_dataset_sample_count(os.path.join(pcap_path, "splitcap"))
    else:
        dataset_length, labels = open_dataset_deal.statistic_dataset_sample_count(pcap_path)

    for index in range(len(dataset_length)):
        if dataset_length[index] < samples[0]:
            print("label %s has less sample's number than defined samples %d" % (labels[index], samples[0]))
            new_samples[index] = dataset_length[index]
    return new_samples

def _build_arg_parser():
    parser = argparse.ArgumentParser(
        description="Generate fine-tuning datasets from split PCAP samples.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--pcap-path", default=pcap_path, required=pcap_path is None,
                        help="Required input split pcap root. Expected layout: PCAP_PATH/<label>/*.pcap or nested split output. Can also be provided with PCAP_PATH.")
    parser.add_argument("--dataset-save-path", default=dataset_save_path,
                        help="Directory for dataset.json, picked_file_record, and cached .npy files.")
    parser.add_argument("--dataset-dir", default=dataset_dir,
                        help="Directory for train/test/valid TSV files.")
    parser.add_argument("--samples", default="5000",
                        help="Samples per class. Use one integer for all classes, or comma-separated per-class counts.")
    parser.add_argument("--features", default="payload",
                        help="Comma-separated feature names. Current main pipeline normally uses payload.")
    parser.add_argument("--dataset-level", choices=["packet", "flow"], default=dataset_level,
                        help="Feature extraction level matching the split data.")
    parser.add_argument("--category", type=int, default=_category,
                        help="Number of classes/categories.")
    parser.add_argument("--models", default="pre-train",
                        help="Comma-separated output model modes. Default writes TSV files for pre-train mode.")
    parser.add_argument("--splitcap-finish", action="store_true",
                        help="Count existing splitcap samples and cap requested samples by available files.")
    parser.add_argument("--open-dataset-not-pcap", action="store_true",
                        help="Convert non-pcap/open dataset files to pcap before dataset generation.")
    parser.add_argument("--file2dir", action="store_true",
                        help="Move pcap files into label directories named after each pcap file.")
    parser.add_argument("--log-file", default=argparse.SUPPRESS,
                        help="Log file path. Defaults to ./logs/finetune_generate.log.")
    parser.add_argument("--log-level", default=os.environ.get("LOG_LEVEL", "INFO"),
                        help="Logging level.")
    return parser

if __name__ == '__main__':
    args = _build_arg_parser().parse_args()
    args.log_file = getattr(args, "log_file", os.environ.get("LOG_FILE")) or _default_log_file()
    configure_logging(args.log_file, args.log_level)
    dataset_generation.configure_logging(args.log_file, args.log_level)

    if not os.path.isdir(args.pcap_path):
        raise FileNotFoundError("Input --pcap-path does not exist or is not a directory: %s" % args.pcap_path)

    _category = args.category
    dataset_dir = args.dataset_dir
    pcap_path = args.pcap_path
    dataset_save_path = args.dataset_save_path
    samples = _parse_csv_ints(args.samples)
    features = _parse_csv_strings(args.features)
    dataset_level = args.dataset_level
    train_model = _parse_csv_strings(args.models)

    open_dataset_not_pcap = args.open_dataset_not_pcap
    
    if open_dataset_not_pcap:
        #open_dataset_deal.dataset_file2dir(pcap_path)
        for p,d,f in os.walk(pcap_path):
            for file in f:
                target_file = file.replace('.','_new.')
                open_dataset_deal.file_2_pcap(os.path.join(p, file), os.path.join(p, target_file))
                if '_new.pcap' not in file:
                    os.remove(os.path.join(p, file))

    file2dir = args.file2dir
    if file2dir:
        open_dataset_deal.dataset_file2dir(pcap_path)

    classified_path, label_counts = open_dataset_deal.classify_flat_pcap_root(pcap_path)
    if classified_path != pcap_path:
        LOGGER.info("Input pcap root was classified by file name: source=%s classified=%s labels=%d files=%d counts=%s",
                    pcap_path, classified_path, len(label_counts), sum(label_counts.values()), label_counts)
        pcap_path = classified_path

    splitcap_finish = args.splitcap_finish
    if splitcap_finish:
        samples = count_label_number(samples)
    else:
        if len(samples) == 1:
            samples = samples * _category
        elif len(samples) != _category:
            raise ValueError("--samples must be one integer or %d comma-separated integers." % _category)

    ml_experiment = 0

    dataset_extract(train_model)

#!/usr/bin/python3
#-*- coding:utf-8 -*-

import os

from main import unlabel_data

def deal_label():
    lower_label = [23,24,35,44,76,94,95]
    lower_label.extend([22,28,52,62,67,102,104])
    lower_label.sort()
    return lower_label

def deal_finetuning(excluding_label):
    dataset_path = os.environ.get("DATASET_PATH", os.path.join(os.getcwd(), "datasets", "cstnet-tls1.3"))
    save_dataset_path = dataset_path
    with open(os.path.join(dataset_path, "train_dataset.tsv"),'r') as f:
        train_data = f.read().split('\n')[1:]
    with open(os.path.join(dataset_path, "valid_dataset.tsv"),'r') as f:
        valid_data = f.read().split('\n')[1:]
    with open(os.path.join(dataset_path, "test_dataset.tsv"),'r') as f:
        test_data = f.read().split('\n')[1:]
    for label_number in excluding_label:
        train_pop_index = []
        valid_pop_index = []
        test_pop_index = []
        for index in range(len(train_data)):
            if str(label_number)+'\t' in train_data[index]:
                train_pop_index.append(index)
        for counter,index in enumerate(train_pop_index):
            index = index - counter
            train_data.pop(index)

        for index in range(len(valid_data)):
            if str(label_number)+'\t' in valid_data[index]:
                valid_pop_index.append(index)
        for counter,index in enumerate(valid_pop_index):
            index = index - counter
            valid_data.pop(index)

        for index in range(len(test_data)):
            if str(label_number)+'\t' in test_data[index]:
                test_pop_index.append(index)
        for counter,index in enumerate(test_pop_index):
            index = index - counter
            test_data.pop(index)
            
    label_number = 120
    count = 0
    while label_number > 105:
        for index in range(len(train_data)):
            data = train_data[index]
            if str(label_number)+'\t' in data:
                new_data = data.replace(str(label_number)+'\t',str(excluding_label[count])+'\t')
                train_data[index] = new_data

        for index in range(len(valid_data)):
            if str(label_number)+'\t' in valid_data[index]:
                new_data = valid_data[index].replace(str(label_number)+'\t',str(excluding_label[count])+'\t')
                valid_data[index] = new_data

        for index in range(len(test_data)):
            if str(label_number)+'\t' in test_data[index]:
                new_data = test_data[index].replace(str(label_number)+'\t',str(excluding_label[count])+'\t')
                test_data[index] = new_data
                
        label_number -= 1
        count += 1
    
    with open(os.path.join(save_dataset_path, "train_dataset.tsv"),'w') as f:
        f.write("label\ttext_a\n")
        for data in train_data:
            f.write(data+'\n')
    with open(os.path.join(save_dataset_path, "valid_dataset.tsv"),'w') as f:
        f.write("label\ttext_a\n")
        for data in valid_data:
            f.write(data+'\n')
    test_dataset_path = os.path.join(save_dataset_path, "test_dataset.tsv")
    with open(test_dataset_path,'w') as f:
        f.write("label\ttext_a\n")
        for data in test_data:
            f.write(data+'\n')
            
    deal_result = input("please delete the last blank line in %s and input '1'"%test_dataset_path)
    if deal_result == '1':
        unlabel_data(test_dataset_path)
    return 0

if __name__ == '__main__':
    excluding_laebl = deal_label()
    deal_finetuning(excluding_laebl)

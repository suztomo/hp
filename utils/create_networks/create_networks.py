#!/usr/bin/env python
# -*- encoding:utf-8 -*-


import yaml
from pdb import set_trace as st
import os
from types import *
from shutil import copyfile

STRUCTURE_FILE='../structure.yaml'
NETWORK_ENTRY_NAME = "networks"

def create_node(netmask, network, machine_addr):
    print(machine_addr)
    for i in range(4):
        machine_addr[i] = (machine_addr[i] & ~netmask[i]) | network[i];
    print(machine_addr)

def create_network(network_info):
    netmask = map(int, network_info['netmask'].split('.'))
    ip_addr_base = map(int, network_info['network'].split('.'))
    if len(netmask) != 4 or len(ip_addr_base) != 4:
        print("invalid configuration.")
        print(network_info)
        exit()
    for machine in network_info['machines']:
        machine_addr = [0] * 4
        if type(machine['address']) is StringType:
            machine_addr_tmp = map(int, machine['address'].split('.'))
            ma_len = len(machine_addr_tmp)
            for i in range(ma_len):
                machine_addr[-i-1] = machine_addr_tmp[-i-1]
        else:
            machine_addr[-1] = machine['address']
        create_node(netmask, ip_addr_base, machine_addr)

def main():
    text = open(STRUCTURE_FILE).read()
    data = yaml.load(text)
    if not NETWORK_ENTRY_NAME in data:
        exit()
    for k in data[NETWORK_ENTRY_NAME].keys():
        print("Creating network: %s" % k)
        create_network(data[NETWORK_ENTRY_NAME][k])

if __name__ == '__main__':
    main()

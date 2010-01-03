#!/usr/bin/env python
# -*- encoding:utf-8 -*-


import yaml
from pdb import set_trace as st
import os
from types import *
from shutil import copyfile

STRUCTURE_FILE='../structure.yaml'
NETWORK_ENTRY_NAME = "networks"
FILE_NODECONFIG_IP = "/sys/kernel/security/hp/node_ip"

def create_node(node, netmask, network, machine_addr):
    print(machine_addr)
    for i in range(4):
        machine_addr[i] = (machine_addr[i] & ~netmask[i]) | network[i];
    print(machine_addr)
    f = open(FILE_NODECONFIG_IP, "w")
    # see hp/sysfs/nodeconf.c
    f.write("%s %s.%s.%s.%s\n" % (node, machine_addr[0], machine_addr[1],
                                  machine_addr[2], machine_addr[3]))
    f.close()


def create_network(network_info):
    netmask = map(int, network_info['netmask'].split('.'))
    ip_addr_base = map(int, network_info['network'].split('.'))
    if len(netmask) != 4 or len(ip_addr_base) != 4:
        print("invalid configuration.")
        print(network_info)
        exit()
    for machine in network_info['machines']:
        machine_addr = [0] * 4
        if type(machine['address']) is StringType: # e.g. "11.102"
            machine_addr_tmp = map(int, machine['address'].split('.'))
            ma_len = len(machine_addr_tmp)
            for i in range(ma_len):
                machine_addr[-i-1] = machine_addr_tmp[-i-1]
        else:
            machine_addr[-1] = machine['address']
        node = machine['hp_node']
        create_node(node, netmask, ip_addr_base, machine_addr)

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

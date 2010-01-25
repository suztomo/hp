#!/usr/bin/env python
# -*- coding: utf-8 -*-


import yaml
from pdb import set_trace as st
import os
from types import *
from shutil import copyfile
from subprocess import call
import getopt, sys

STRUCTURE_FILE='../structure.yaml'
NETWORK_ENTRY_NAME = "networks"
VARIABLES_ENTRY_NAME = "variables"
FILE_NODECONFIG_IP = "/sys/kernel/security/hp/node_ip"
HPEXEC_SCRIPT = "hputil.py"

verbose = False

def configure_node(node, netmask, network, machine_addr, vport, rport):
    for i in range(4):
        machine_addr[i] = (machine_addr[i] & ~netmask[i]) | network[i];
    write_nodeinfo(node, machine_addr, vport, rport)

def write_nodeinfo(hp_node, machine_addr, vport, rport):
    f = open(FILE_NODECONFIG_IP, "w")
    # see hp/sysfs/nodeconf.c
    line = "%s %s.%s.%s.%s:%s %s" % (hp_node, machine_addr[0], machine_addr[1],
                                       machine_addr[2], machine_addr[3],
                                       vport, rport)
    if verbose:
        print('writing "%s" to %s' % (line, FILE_NODECONFIG_IP))
    f.write("%s\n" % line)
    f.close()

def check_machines_consistency(machines):
    for m1 in machines:
        if (not 'hp_node' in m1
            or not 'address' in m1):
            error("machine must have hp_node and address")
            print(m1)
            return False
    rport_owned = {}
    for m1 in machines:
        for m2 in machines:
            if (m1 == m2):
                continue
            if (m1['hp_node'] == m2['hp_node']):
                error("hp_node is not unique\n")
                print(m1)
                print(m2)
                return False
            if (m1['address'] == m2['address']):
                error("Address is not unique\n")
                print(m1)
                print(m2)
                return False
        if 'ports' in m1:
            pdict = m1['ports']
            for k in pdict:
                if pdict[k] in rport_owned:
                    error("real port is already chosen\n")
                    return False
                rport_owned[pdict[k]] = 1
    return True
                

def create_network(network_info, vars):
    netmask = map(int, network_info['netmask'].split('.'))
    ip_addr_base = map(int, network_info['network'].split('.'))
    if len(netmask) != 4 or len(ip_addr_base) != 4:
        error("invalid configuration.")
        error(network_info)
        exit()

    if (check_machines_consistency(network_info['machines'])):
        if verbose:
            print("  structure consistency check: OK\n")
    else:
        error("  structure consistency check: NG\n")
        sys.exit(1)
    for machine in network_info['machines']:
        if ((not 'hp_node' in machine)
            or (not 'address' in machine)):
            error("Invald configuration")
            error(machine)
            continue
        machine_addr = [0] * 4
        if type(machine['address']) is StringType: # e.g. "11.102"
            machine_addr_tmp = map(int, machine['address'].split('.'))
            ma_len = len(machine_addr_tmp)
            for i in range(ma_len):
                machine_addr[-i-1] = machine_addr_tmp[-i-1]
        else:
            machine_addr[-1] = machine['address']
        node = machine['hp_node']
        if 'ports' in machine:
            pdict = machine['ports']
            for vport in pdict:
                rport = pdict[vport]
                try:
                    configure_node(node, netmask, ip_addr_base, machine_addr,
                                   vport, rport)
                except IOError:
                    error("Cannot write to %s\n" % FILE_NODECONFIG_IP)
                    sys.exit(2)


def error(message):
    sys.stderr.write(message)


def main():
    global verbose
    sfile = STRUCTURE_FILE
    try:
        opts, args = getopt.getopt(sys.argv[1:], "dh",
                                   ["debug", "help"])
    except getopt.GetoptError:
        usage()
        sys.exit(2)

    if len(args) != 1:
        error("specify configure file\n")
        sys.exit(2)
    sfile = args[0]

    for o, a in opts:
        if o == "-h" or o == "--help":
            usage()
            sys.exit(2)
        if o == "-d" or o == "--debug":
            verbose = True

    if verbose:
        print("Structure file : %s\n" % sfile)

    try:
        text = open(sfile).read()
        data = yaml.load(text)
    except IOError:
        error("Cannot read %s\n" % sfile)
        sys.exit(2)
    vars = {}
    if VARIABLES_ENTRY_NAME in data:
        vars = data[VARIABLES_ENTRY_NAME]
        if verbose:
            print("Variables:\n")
            for k in vars:
                print("  $%s : %s\n" % (k, vars[k]))
    if (not NETWORK_ENTRY_NAME in data
        or not type(data[NETWORK_ENTRY_NAME]) is DictType):
        error("Invalid format of %s entry\n" % NETWORK_ENTRY_NAME)
        sys.exit(2)
    for k in data[NETWORK_ENTRY_NAME].keys():
        print("Creating network: %s" % k)
        create_network(data[NETWORK_ENTRY_NAME][k], vars)

if __name__ == '__main__':
    main()

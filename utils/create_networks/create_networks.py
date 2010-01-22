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


def replace_vars(s, env):
    for k in env:
        vname1 = "$%s" % k
        vname2 = "${%s}" % k
        s = s.replace(vname1, env[k])
        s = s.replace(vname2, env[k])
    return s

def expand_commands(cmds, env):
    return [replace_vars(e, env) for e in cmds]

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

def run_command_in_node(hp_node, cmd, args):
    call([HPEXEC_SCRIPT, "-d", "-n", str(hp_node), "-e", cmd]+args)

def run_daemons(hp_node, daemons):
    for d in daemons:
        if verbose:
            print("  Node %d invokes %s" % (hp_node, d))
        ds = d.split(" ")
        cmd = ds[0]
        args = ds[1:]
        run_command_in_node(hp_node, cmd, args)

def create_network(network_info, vars):
    netmask = map(int, network_info['netmask'].split('.'))
    ip_addr_base = map(int, network_info['network'].split('.'))
    if len(netmask) != 4 or len(ip_addr_base) != 4:
        error("invalid configuration.")
        error(network_info)
        exit()
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
        if 'daemons' in machine:
            if not 'ports' in machine:
                error("Port is not specified but daemon is specified\n")
                print(machine)
                continue
            daemons = expand_commands(machine['daemons'], vars)
            run_daemons(node, daemons)


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

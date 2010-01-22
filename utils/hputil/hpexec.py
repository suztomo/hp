#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pdb import set_trace as st
import os
import getopt, sys
from types import *
from subprocess import call

SCRIPT_NAME = "hpexec"
FILE_SELFCONF = "/sys/kernel/security/hp/selfconf"
FILE_NODECONFIG_IP = "/sys/kernel/security/hp/node_ip"

def mark_self(hp_node):
    f = open(FILE_SELFCONF, "w")
    f.write("%d\n" % hp_node)
    f.close()

def create_node(node, machine_addr, vport, rport):
    f = open(FILE_NODECONFIG_IP, "w")
    # see hp/sysfs/nodeconf.c
    f.write("%d %s:%d %d\n" % (node, machine_addr, vport, rport))
    f.close()

def exec_cmd(lst):
    output = call(lst)
    return output

def usage():
    message = """
Honeypot execution utility

Runs a command in a honeypot environment specified in <hp_node>

Usage:
  hpexec -n <hp_node>
        [-a <address>]
        [-v <virtual port>]
        [-r <real port>]
        COMMAND
"""
    print message

verbose = False

def main():
    hp_node = -1
    ip_addr = ""
    ip_vport = -1
    ip_rport = -1
    command = ""
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hvn:a:v:r:",
                                   ["help", "verbose", "node=",
                                    "addr:", "vport=", "rport="])
    except getopt.GetoptError:

        usage()
        sys.exit(2)

    if len(args) == 0:
        error("speicfy command")
        usage()
        sys.exit(2)
    command = args

    for o, a in opts:
        if o == "-v" or o == "--verbose":
            verbose = True
        if o == "-h" or o == "--help":
            usage()
            sys.exit()
        if o == "-n" or o == "--node":
            hp_node = int(a)
        if o == "-a" or o == "--addr":
            ip_addr = o
        if o == "-v" or o == "--vport":
            ip_vport = int(a)
        if o == "-r" or o == "--rport":
            ip_rport = int(a)

    try:
        mark_self(hp_node)
    except OSError:
        error("Wrong with selfconf %s", FILE_SELFCONF)

    if len(ip_addr) > 0:
        if (ip_vport == -1 or ip_vport == -1):
            error("If add network information, "
                  "specify vport, rport and address")
            usage()
            sys.exit(2)
        create_node(hp_node, ip_addr, ip_vport, ip_rport)
            
    # this should be return immediately
    
    exec_cmd(command)

def error(message):
    sys.stderr.write(message)

if __name__ == "__main__":
    main()
    

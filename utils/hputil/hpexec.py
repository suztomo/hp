#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Tool that executes a commands in a honeypot environment
#

from pdb import set_trace as st
import os
import getopt, sys
from subprocess import call

UTIL_SCRIPT_NAME = "hputil.py"
FILE_SELFCONF = "/sys/kernel/security/hp/selfconf"
FILE_NODECONFIG_IP = "/sys/kernel/security/hp/node_ip"

verbose = False

def mark_self(hp_node):
    f = open(FILE_SELFCONF, "w")
    line = "%d" % hp_node
    if verbose:
        print 'writing "%s" to %s' % (line, FILE_SELFCONF)
    f.write("%s\n" % line)
    f.close()

def create_node(node, machine_addr, vport, rport):
    f = open(FILE_NODECONFIG_IP, "w")
    # see hp/sysfs/nodeconf.c
    line = "%d %s:%d %d" % (node, machine_addr, vport, rport)
    if verbose:
        print 'writing "%s" to %s' % (line, FILE_NODECONFIG_IP)
    f.write("%s\n" % line)
    f.close()

def exec_cmd(lst):
    if verbose:
        cmd = " ".join(lst)
        print "Executing %s\n" % cmd
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



def main():
    hp_node = -1
    ip_addr = ""
    ip_vport = -1
    ip_rport = -1
    command = ""
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hdn:a:v:r:",
                                   ["help", "debug", "node=",
                                    "addr:", "vport=", "rport="])
    except getopt.GetoptError:
        usage()
        sys.exit(1)

    if len(args) == 0:
        error("speicfy command")
        usage()
        sys.exit(1)

    hputil_command = [UTIL_SCRIPT_NAME]
    for o, a in opts:
        if o == "-d" or o == "--debug":
            verbose = True
            hputil_command.append("-d")
        if o == "-h" or o == "--help":
            usage()
            sys.exit()
        if o == "-n" or o == "--node":
            hp_node = int(a)
            hputil_command.append("-n")
            hputil_command.append(a)
        if o == "-a" or o == "--addr":
            ip_addr = a
            hputil_command.append("-a")
            hputil_command.append(a)
        if o == "-v" or o == "--vport":
            ip_vport = int(a)
            hputil_command.append("-v")
            hputil_command.append(a)
        if o == "-r" or o == "--rport":
            ip_rport = int(a)
            hputil_command.append("-r")
            hputil_command.append(a)
    hputil_command += ["-e"] + args

    if (hp_node < 0):
        error("Specify node id\n")
        usage()
        sys.exit(1)

    if len(ip_addr) > 0:
        if (ip_vport == -1 or ip_vport == -1):
            error("If add network information, "
                  "specify vport, rport and address")
            usage()
            sys.exit(2)
    call(hputil_command)


def error(message):
    sys.stderr.write(message)

if __name__ == "__main__":
    main()
    

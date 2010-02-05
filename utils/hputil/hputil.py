#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Tool that executes a commands in a honeypot environment
#

from pdb import set_trace as st
import os
import getopt, sys
from subprocess import call

SCRIPT_NAME = "hpexec"
FILE_NODECONFIG_IP = "/sys/kernel/security/hp/node_ip"
FILE_SELFCONF = "/sys/kernel/security/hp/selfconf"

verbose = False

def usage():
    message = """
Honeypot configuration utility

Configures node-address-port relation

Usage:
  hputil -n <hp_node>          : honeypot virtual node
         -a <address>          : virtual address
         -v <virtual port>     : virtual port
         -r <real port>        : real port
         -e                    : execution flag
         -d                    : debug mode
         COMMAND               : commands to be execute (if -e is specified)

"""
    print message


def mark_self(hp_node):
    f = open(FILE_SELFCONF, "w")
    line = "%d" % hp_node
    if verbose:
        print '  writing "%s" to %s' % (line, FILE_SELFCONF)
    f.write("%s\n" % line)
    f.close()

def create_node(node, machine_addr, vport, rport):
    f = open(FILE_NODECONFIG_IP, "w")
    # see hp/sysfs/nodeconf.c
    line = "%d %s:%d %d" % (node, machine_addr, vport, rport)
    if verbose:
        print 'writing "%s" to %s\n' % (line, FILE_NODECONFIG_IP)
    f.write("%s\n" % line)
    f.close()

def exec_cmd(lst):
    if verbose:
        cmd = " ".join(lst)
        print "  executing %s" % cmd
    output = call(lst)
    return output

def main():
    global verbose
    hp_node = -1
    ip_addr = ""
    ip_vport = -1
    ip_rport = -1
    command = []
    did_something = False
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hdn:a:v:r:e",
                                   ["help", "debug", "node=",
                                    "addr:", "vport=", "rport=", "exec"])
    except getopt.GetoptError:
        usage()
        sys.exit(2)

    if len(opts) == 0:
        usage()
        sys.exit(2)

    for o, a in opts:
        if o == "-d" or o == "--debug":
            verbose = True
        if o == "-h" or o == "--help":
            usage()
            sys.exit()
        if o == "-n" or o == "--node":
            hp_node = int(a)
        if o == "-a" or o == "--addr":
            ip_addr = a
        if o == "-v" or o == "--vport":
            ip_vport = int(a)
        if o == "-r" or o == "--rport":
            ip_rport = int(a)
        if o == "-e" or o == "--exec":
            command = args

    if (hp_node < 0):
        error("Specify node id\n")
        usage()
        sys.exit(2)

    if len(ip_addr) > 0:
        if (ip_vport == -1 or ip_vport == -1):
            error("If add network information, "
                  "specify vport, rport and address\n")
            usage()
            sys.exit(2)
        try:
            create_node(hp_node, ip_addr, ip_vport, ip_rport)
            did_something = True
        except IOError:
            error("Wrong with nodeconf %s\n" % FILE_NODECONFIG_IP)
            sys.exit(2)


    # this should be return immediately
    if len(command) > 0:
        if hp_node < 0:
            error("Specify node id\n")
            sys.exit(1)
        try:
            mark_self(hp_node)
        except IOError:
            error("Wrong with selfconf %s\n" % FILE_SELFCONF)
            sys.exit(1)
        try:
            exec_cmd(command)
        except OSError, e:
            error("%s\nCannot execute the command %s" % (e.strerror,
                                                         (" ".join(command))))
            sys.exit(1)
        did_something = True

    if not did_something:
        error("Nothing done\n")

def error(message):
    sys.stderr.write(message)

if __name__ == "__main__":
    main()
    

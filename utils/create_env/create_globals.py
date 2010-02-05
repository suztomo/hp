#!/usr/bin/env python
# -*- coding: utf-8 -*-

import yaml
from pdb import set_trace as st
import os
from types import *
from shutil import copyfile
from subprocess import call
import getopt, sys
from re import compile as rcomp

STRUCTURE_FILE='../structure.yaml'
GLOBAL_ENTRY_NAME = "globals"
VARIABLES_ENTRY_NAME = "variables"
FILE_PORTCONFIG = "/sys/kernel/security/hp/node_port"
HPEXEC_SCRIPT = "hputil.py"

regex = rcomp("\((?P<var>\$\w+)(\*(?P<mul>\d+))?\+(?P<base>\d+)\)")

def string_replace_vars(s, env):
    m = regex.search(s)
    if m:
        v = m.group('var')
        b = m.group('base')
        bi = int(b)
        mul = m.group('mul')
        if v not in env:
            print("no such variables")
            return s
        vi = int(env[v])
        if mul:
            vi *= int(mul)
        s = str(vi + bi)
    else:
        for k in env:
            s = s.replace(k, env[k])
    return s

def dict_replace_vars(dic, env):
    ret = {}
    for k in dic:
        newk = k
        if type(k) is StringType:
            # key may be IntType
            newk = string_replace_vars(k, env)
        ret[newk] = do_replace_vars_data(dic[k], env)
    return ret

def list_replace_vars(lst, env):
    return [do_replace_vars_data(s,env) for s in lst]

def do_replace_vars_data(d, env):
    if type(d) is DictType:
        return dict_replace_vars(d, env)
    if type(d) is ListType:
        return list_replace_vars(d, env)
    if type(d) is StringType:
        return string_replace_vars(d, env)
    return d

def replaced_vars_data(d, env):
    if not type(env) is DictType:
        print("vars should be dict")
        return
    if type(d) is StringType:
        print("data should not be string")
        return
    return do_replace_vars_data(d, env)

def expand_commands(cmds, env):
    return do_replace_vars_data(cmds, env)

def run_command_in_node(hp_node, cmd, args):
    if verbose:
        call([HPEXEC_SCRIPT, "-n", "-d", str(hp_node), "-e", cmd]+args)
    else:
        call([HPEXEC_SCRIPT, "-n", str(hp_node), "-e", cmd]+args)


def run_daemons(hp_node, daemons):
    for d in daemons:
        print("  Node %s invokes %s" % (hp_node, d))
        ds = d.split(" ")
        cmd = ds[0]
        args = ds[1:]
        run_command_in_node(hp_node, cmd, args)

def notify_port_map(hp_node, port):
    line = "%d %d" % (hp_node, port)
    try:
        f = open(FILE_PORTCONFIG, "w")
    except IOError:
        error("Cannot open as writing %s\n" % FILE_PORTCONFIG)
        sys.exit(1)
    if verbose:
        print 'writing "%s" to %s\n' % (line, FILE_PORTCONFIG)
    f.write("%s\n" % line)
    f.close()

def run_machine(machine, env):
    daemons = machine.get('daemons', [])
    daemons = expand_commands(daemons, env)
    hp_node = int(machine.get('hp_node', -1))
    if hp_node == -1:
        print("machine has invalid hp_node")
        st()
        sys.exit(1)
    for d in daemons:
        if 'port' not in d or 'command' not in d:
            print("machine does not have port or command")
            st()
            sys.exit(1)
        port = int(d['port'])
        notify_port_map(hp_node, port)
        run_command_in_node
    run_daemons(hp_node, daemons)

def create_globals(data, env):
    if 'machines' not in data:
        print("machines is not in %s" % GLOBAL_ENTRY_NAME)
        sys.exit(1)
    machines = data['machines']
    for m in machines:
        run_machine(m, env)


def usage():
    message = """
Creates global daemons

create_global_dummys.py <config.yaml>

  options:
    -h                     show help
    -d                     with debug
"""
    print message

def error(message):
    sys.stderr.write(message)


def main():
    global verbose
    sfile = STRUCTURE_FILE
    try:
        opts, args = getopt.getopt(sys.argv[1:], "dh",
                                   ["debug", "help"]);
    except getopt.GetoptError:
        usage()
        sys.exit(2)

    for o, a in opts:
        if o == "-h" or o == "--help":
            usage()
            sys.exit(0)
        elif o == "-d" or o == "--debug":
            verbose = True
    env = {}
    sfile = args[0]
    try:
        text = open(sfile).read()
        data = yaml.load(text)
    except IOError:
        error("Cannot read %s\n" % sfile)
        sys.exit(1)

    if VARIABLES_ENTRY_NAME in data:
        env = data[VARIABLES_ENTRY_NAME]
        if verbose:
            print("Variables:")
            for k in env:
                print("  $%s : %s" % (k, env[k]))

    if GLOBAL_ENTRY_NAME not in data:
        error("Invalid format of %s entry\n" % GLOBAL_DUMMY_ENTRY_NAME)
        sys.exit(1)

    create_globals(data[GLOBAL_ENTRY_NAME], env)

if __name__ == '__main__':
    main()


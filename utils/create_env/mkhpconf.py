#!/usr/bin/env python
# -*- coding: utf-8 -*-

import yaml
import sys
from pdb import set_trace as st
from types import *
from copy import deepcopy
from re import compile as rcomp

DEFAULT_FILE = 'structure.default.yaml'
OUTPUT_FILE = 'structure.output.yaml'
from create_home import (HOME_DIR_ENTRY_NAME, VAR_DIR_ENTRY_NAME,
                         FS_ENTRY_NAME)
from create_networks import (NETWORK_ENTRY_NAME)

from create_globals import (GLOBAL_ENTRY_NAME)

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
        
        s = s[:m.start()] + str(vi + bi) + s[m.end():]
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

def auto_expand_dict(dic, e = None):
    if not 'auto' in dic:
        return
    if not e:
        e = dic['auto']
    f = e['from']
    t = e['to']
    d = e['data']
    for i in range(f, t+1):
        dic[i] = replaced_vars_data(d, {'$I': ("%d" % i)})
    del(dic['auto'])

def auto_expand_list(lst, e):
    f = e['from']
    t = e['to']
    d = e['data']
    for i in range(f, t+1):
        lst.append(replaced_vars_data(d, {'$I': ("%d" %i)}))
    
def main():
    f = DEFAULT_FILE
    if len(sys.argv) == 2:
        f = sys.argv[1]
    default_str = open(f).read()
    data = yaml.load(default_str)
    if (FS_ENTRY_NAME not in data or
        VAR_DIR_ENTRY_NAME not in data[FS_ENTRY_NAME] or
        HOME_DIR_ENTRY_NAME not in data[FS_ENTRY_NAME]):
        print("cannot find home dir config")
        return
    if (NETWORK_ENTRY_NAME not in data):
        print("cannot find network config")
        return
    h = data[FS_ENTRY_NAME][HOME_DIR_ENTRY_NAME]
    v = data[FS_ENTRY_NAME][VAR_DIR_ENTRY_NAME]
    n = data[NETWORK_ENTRY_NAME]['vnet1']['machines']
    nc = data[NETWORK_ENTRY_NAME]['vnet1']['machines_auto']
    print("generating %s" % OUTPUT_FILE)
    auto_expand_dict(h)
    auto_expand_dict(v)
    auto_expand_list(n, nc)

    if (GLOBAL_ENTRY_NAME not in data):
        print("cannot find global config")
        return
    g = data[GLOBAL_ENTRY_NAME]
    if 'machines_auto' not in g:
        print("cannot find machines_auto in %s" % GLOBAL_ENTRY_NAME)
        return
    if 'machines' not in g:
        print("cannot find machines in %s" % GLOBAL_ENTRY_NAME)
        return
    d = g['machines_auto']
    l = g['machines']
    auto_expand_list(l, d)
    f = open(OUTPUT_FILE, 'w')
    yaml.dump(data, f, encoding='utf8', allow_unicode=True)

if __name__ == '__main__':
    main()

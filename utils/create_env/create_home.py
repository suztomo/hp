#!/usr/bin/env python
# -*- coding: utf-8 -*-


import yaml
import pdb
import os
import sys
from types import *
from shutil import copyfile

HOME_DIR_PATH='/j'
FS_ENTRY_NAME = 'fs'
HOME_DIR_ENTRY_NAME='home_dirs'
VAR_DIR_ENTRY_NAME='var_dirs'
STRUCTURE_FILE='../structure.yaml'

def create_file(parent_dir, filename, filepath):
    print("copying %s to %s/%s" % (filepath, parent_dir, filename));
    copyfile(filepath, "%s/%s" % (parent_dir, filename))

def create_dir(parent_dir, target_dir, next = None):
    """
    Creates the target directory under the parent directory.
    next is None or a dictionary whose keys are the names of the
    subdirectories of target_dir.
    """
    making_dir = parent_dir + '/' + target_dir

    if not os.path.isdir(making_dir):
        print("making %s" % making_dir)
        os.mkdir(making_dir)
    else:
        print("%s already exists" % making_dir)

    if next:
        for k in next.keys():
            if type(next[k]) is StringType:
                create_file(making_dir, k, next[k])
            else:
                create_dir(making_dir, k, next[k])


def main():
    if len(sys.argv) != 2:
        print("specify config yaml")
        return
    f = sys.argv[1]
    text = open(f).read()
    data = yaml.load(text)
    if not FS_ENTRY_NAME in data:
        print("%s is not exists\n" % FS_ENTRY_NAME)
        exit()
    data = data[FS_ENTRY_NAME]
    if not HOME_DIR_ENTRY_NAME in data:
        print("%s is not exists\n" % HOME_DIR_ENTRY_NAME)
        exit()
    if not VAR_DIR_ENTRY_NAME in data:
        print("%s is not exists\n" % VAR_DIR_ENTRY_NAME)
        exit()

    for k in data[HOME_DIR_ENTRY_NAME].keys():
        if not os.path.isdir(HOME_DIR_PATH + ("/%05d" % int(k))):
            create_dir(HOME_DIR_PATH, "/%05d" % int(k))
        create_dir(HOME_DIR_PATH, "%05d/home" % int(k), data[HOME_DIR_ENTRY_NAME][k])
    for k in data[VAR_DIR_ENTRY_NAME].keys():
        if not os.path.isdir(HOME_DIR_PATH + ("/%05d" % int(k))):
            create_dir(HOME_DIR_PATH, "/%05d" % int(k))
        create_dir(HOME_DIR_PATH, "%05d/var" % int(k), data[VAR_DIR_ENTRY_NAME][k])


if __name__ == '__main__':
    main()

#!/usr/bin/env python
# -*- encoding:utf-8 -*-


import yaml
import pdb
import os
from types import *
from shutil import copyfile

HOME_DIR_PATH='/j'
HOME_DIR_ENTRY_NAME='home_dirs'
STRUCTURE_FILE='../structure.yaml'

def create_file(parent_dir, filename, filepath):
    print("copying %s to %s/%s" % (filepath, parent_dir, filename));
    copyfile(filepath, "%s/%s" % (parent_dir, filename))

def create_dir(parent_dir, target_dir, next):
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
    text = open(STRUCTURE_FILE).read()
    data = yaml.load(text)
    if not HOME_DIR_ENTRY_NAME in data:
        exit()
    for k in data[HOME_DIR_ENTRY_NAME].keys():
        create_dir(HOME_DIR_PATH, "%05d" % int(k), data[HOME_DIR_ENTRY_NAME][k])


if __name__ == '__main__':
    main()

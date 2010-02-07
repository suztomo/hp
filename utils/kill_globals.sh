#!/bin/sh
echo "Killing ncwhile (global dummy daemons)"
ps alx |grep ncwhile|grep -v grep|sed -e "s/ \+/ /g" |cut -d' ' -f3 |xargs kill
ps alx |grep "nc -l"|grep -v grep|sed -e "s/ \+/ /g" |cut -d' ' -f3 |xargs kill

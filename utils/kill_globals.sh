#!/bin/sh
echo "Killing ncwhile (global dummy daemons)"
ps alx |grep ncwhile|grep -v grep|sed -e "s/ /\t/g" |cut -f5 |xargs kill
ps alx |grep "nc -l"|grep -v grep|sed -e "s/ /\t/g" |cut -f5 |xargs kill

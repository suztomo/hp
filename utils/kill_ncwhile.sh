#!/bin/sh
echo "Killing newhile (global dummy daemons)"
ps alx |grep ncwhile|sed -e "s/ /\t/g" |cut -f5 |xargs kill
ps alx |grep "nc -l"|sed -e "s/ /\t/g" |cut -f5 |xargs kill
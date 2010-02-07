#!/bin/sh
echo "Killing sshd(s)"
ps alx |grep /usr/src/openssh/sshd |grep -v grep|sed -e "s/ \+/ /g" |cut -d' ' -f3 |xargs kill


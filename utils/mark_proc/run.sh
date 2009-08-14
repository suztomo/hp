#!/bin/zsh
# Marks sshd processes using mark_proc.ko
# Assuming a /sbin/sshd is running
PIDS=`pgrep sshd|tr '\n' '\t'|cut -f 2- |tr '\t' ',' |perl -ple 's/,$//'`
NUM=`pgrep sshd| wc -l`
NUM=`expr $NUM - 1`
echo $NUM
NUMS_LIST=1
I=2
while [ $I -le $NUM ]; do
    NUMS_LIST=$NUMS_LIST,$I
    I=`expr $I + 1`
done
echo "The kernel module fails anyway. type: dmesg"
sudo insmod mark_proc.ko pid_array=$PIDS node_array=$NUMS_LIST

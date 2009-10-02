#!/bin/sh
# Launches apaches on virtual hosts on $FROM_PORT_INDEX to $TO_PORT_INDEX.
# This program uses sshd on firing apaches.
# Make sure that there are sshd-s after
# hp/utils/run_sshd.sh has been executed.
#
# To enter without password using key file, copy the ~/.ssh directories to 
# virtual hosts.
#    for I in {0..10};do
#       NUM=`printf "%05d" $I`;
#       sudo mkdir /j/$NUM/home/suzuki/;
#       sudo chown suzuki:suzuki /j/$NUM/home/suzuki/ ;
#    done
#    for I in {0..10};do NUM=`printf "%05d" $I`;
#       cp -r ~/.ssh /j/$NUM/home/suzuki/ ;
#    done

FROM_PORT_INDEX=$1
TO_PORT_INDEX=$2
SKIP=$3
if ! [ $2 ]; then
    echo "usage: $0 <from_port> <to_port> [<skip>]"
    exit
fi
if ! [ $3 ]; then
    SKIP=1;
fi

I=$FROM_PORT_INDEX
LOOP_COUNT=0

echo "Launching Apache WWW Server on Virtual Hosts [$FROM_PORT_INDEX:$TO_PORT_INDEX:$SKIP]"

while [ $I -lt $TO_PORT_INDEX ]; do
    CMD="ssh suzuki@localhost -p $I apache2ctl start"
    echo $CMD
    $CMD
    LOOP_COUNT=`expr $LOOP_COUNT + 1`
    I=`expr $I + $SKIP`
done

echo "Created $LOOP_COUNT apache instances"




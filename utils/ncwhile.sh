#!/bin/sh
PORT=$1
if [ -z $PORT ]; then
    echo "specify port"
    exit 1
fi
while true; do
nc -l -p $PORT
done

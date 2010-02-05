#!/bin/zsh
PORT=$1
if [ -z $PORT ]; then
    echo "specify port"
    exit 1
fi
/usr/bin/nohup /home/suzuki/hp/utils/ncwhile.sh $PORT &

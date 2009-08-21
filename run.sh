#!/bin/zsh
pkill sshd
make install
cd $HOME/hp/utils/create_networks; python create_networks.py
$HOME/hp/utils/run_sshd.sh 10022 10923 100
cd $HOME/hp/utils/mark_proc; make;./run.sh
cd $HOME/hp
trap 'echo; echo "end"; pkill sshd; make uninstall; exit' 1 2 3 15
while true; do
    sleep 10
done




#!/bin/zsh
SSHD_PORT_FROM=10022
SSHD_PORT_TO=10923
SSHD_PORT_SKIP=100
pkill sshd
make install
cd $HOME/hp/utils/create_networks; python create_networks.py
$HOME/hp/utils/run_sshd.sh $SSHD_PORT_FROM $SSHD_PORT_TO $SSHD_PORT_SKIP
cd $HOME/hp/utils/mark_proc; make;./run.sh
cd $HOME/hp
trap 'echo; echo "end"; pkill sshd; make uninstall; exit' 1 2 3 15
$HOME/hp/experiments/apache2/run_apache.sh $SSHD_PORT_FROM $SSHD_PORT_TO \
    $SSHD_PORT_SKIP
while true; do
    sleep 10
done




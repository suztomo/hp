#!/bin/zsh
SSHD_PORT_FROM=10122
SSHD_PORT_TO=11022
SSHD_PORT_SKIP=100
pkill sshd
make install
utils/create_env/create_networks.py utils/structure.output.yaml
if [ ! -z $1 ];then
    utils/create_env/create_daemons.py utils/structure.output.yaml
fi

# twistd requires two-times pkill(?)
trap 'echo; echo "end"; pkill twistd;pkill twistd;pkill sshd; \
  $HOME/hp/experiments/apache2/kill_apache.sh; make uninstall; \
  $HOME/hp/utils/kill_ncwhile.sh; exit' 1 2 3 15
cd $HOME/hp/utils/tty_server; twistd -y tty_server.py
cd $HOME/hp
while true; do
    sleep 10
done


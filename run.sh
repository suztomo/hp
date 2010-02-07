#!/bin/zsh
make install
utils/create_env/create_networks.py utils/structure.output.yaml
utils/create_env/create_globals.py utils/structure.output.yaml
if [ ! -z $1 ];then
    utils/create_env/create_daemons.py utils/structure.output.yaml
fi


# twistd requires two-times pkill(?)
trap 'echo; echo "end"; pkill twistd;pkill twistd;\
  make uninstall; \
  $HOME/hp/utils/kill_sshd.sh; \
  $HOME/hp/experiments/apache2/kill_apache.sh;\
  $HOME/hp/utils/kill_globals.sh; exit' 1 2 3 15
cd $HOME/hp/utils/tty_server; twistd -y tty_server.py
cd $HOME/hp
while true; do
    sleep 10
done


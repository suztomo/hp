cp ssh_worm.sh worm/
chmod 755 worm/ssh_worm.sh
tar cvf worm.tar worm
scp -P 10122 worm.tar suzuki@localhost:~/
scp -P 10122 already.txt suzuki@localhost:~/
scp -P 10122 run_worm_init.sh suzuki@localhost:~/;chmod 755 run_worm_init.sh
ssh suzuki@localhost -p 10122 sh run_worm_init.sh

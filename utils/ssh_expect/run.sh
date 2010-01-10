cp ssh_worm.sh worm/
chmod 755 worm/ssh_worm.sh
tar cvf worm.tar worm
scp -P 10022 worm.tar suzuki@localhost:~/
scp -P 10022 already.txt suzuki@localhost:~/
ssh suzuki@localhost -p 10022 sh run_worm_init.sh

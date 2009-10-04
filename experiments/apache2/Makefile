TARGET=apache2ctl_suid
all:
	gcc -Wall -o $(TARGET) $(TARGET).c
	sudo chown root:root $(TARGET)
	sudo cp $(TARGET) /usr/sbin/
	sudo chmod +s /usr/sbin/$(TARGET)

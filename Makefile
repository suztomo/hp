TARGET=honeypot
obj-m += $(TARGET).o
honeypot-objs := syscalls/networks.o syscalls/paths.o \
	proc/procfs_hack.o \
	sysfs/root.o \
	hp.o


all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

check-syntax:
	LANG=C make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

install:
	sudo insmod $(TARGET).ko

uninstall:
	sudo rmmod $(TARGET)

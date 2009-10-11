TARGET=honeypot
obj-m += $(TARGET).o
honeypot-objs := syscalls/networks.o syscalls/syscall_hooks.o \
	tty/tty_hooks.o \
	proc/procfs_hack.o \
	sysfs/nodeconf.o sysfs/root.o sysfs/tty_output/root.o \
	sysfs/tty_output/tty_file.o \
	common.o hp.o


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

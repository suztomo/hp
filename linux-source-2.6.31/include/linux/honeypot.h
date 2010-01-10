#ifndef _LINUX_HONEYPOT_H
#define _LINUX_HONEYPOT_H
#include <linux/tty.h>
#include <linux/utsname.h>
#include <linux/socket.h>

/*

  Test for honeypot system
  The function should be replaced via kernel module.

 */

struct tgid_iter {
	unsigned int tgid;
	struct task_struct *task;
};

typedef int (*proc_pid_readdir_hook)(struct tgid_iter *iter);
typedef int (*do_getname_hook) (const char __user *filename, char *page);
typedef void (*sys_getcwd_hook) (char *buf, unsigned long *len);
typedef void (*do_tty_write_hook) (struct tty_struct *tty, size_t size);
typedef void (*newuname_hook) (struct new_utsname *utsn);
typedef void (*connect_hook) (struct sockaddr_storage *address, int addrlen);

struct honeypot_hooks_s {
  proc_pid_readdir_hook in_proc_pid_readdir;
  do_getname_hook in_getname;
  sys_getcwd_hook in_sys_getcwd;
  proc_pid_readdir_hook dummy;
  do_tty_write_hook in_do_tty_write;
  newuname_hook in_newuname;
  connect_hook in_connect;
  rwlock_t lock;
};

extern struct honeypot_hooks_s honeypot_hooks;

#endif // _LINUX_HONEYPOT_H

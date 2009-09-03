#ifndef _LINUX_HONEYPOT_H
#define _LINUX_HONEYPOT_H

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

struct honeypot_hooks_s {
  proc_pid_readdir_hook in_proc_pid_readdir;
  do_getname_hook in_getname;
  sys_getcwd_hook in_sys_getcwd;
  proc_pid_readdir_hook dummy;
  rwlock_t lock;
};

extern struct honeypot_hooks_s honeypot_hooks;

#endif // _LINUX_HONEYPOT_H

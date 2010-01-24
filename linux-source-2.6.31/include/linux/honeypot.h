#ifndef _LINUX_HONEYPOT_H
#define _LINUX_HONEYPOT_H
#include <linux/tty.h>
#include <linux/utsname.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/if.h>


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
typedef void (*inet_gifconf_hook) (struct ifreq *ifr);
typedef void (*devinet_siocgifaddr_hook) (struct sockaddr_in *sin);
typedef void (*sys_bind_hook) (struct sockaddr_storage *address, int addrlen);
typedef void (*sys_sendto_hook) (struct sockaddr_storage *address, int addrlen);

struct honeypot_hooks_s {
  proc_pid_readdir_hook in_proc_pid_readdir;
  do_getname_hook in_getname;
  sys_getcwd_hook in_sys_getcwd;
  proc_pid_readdir_hook dummy;
  do_tty_write_hook in_do_tty_write;
  newuname_hook in_newuname;
  connect_hook in_sys_connect;
  inet_gifconf_hook in_inet_gifconf;
  devinet_siocgifaddr_hook in_devinet_siocgifaddr;
  sys_bind_hook in_sys_bind;
  sys_sendto_hook in_sys_sendto;
  rwlock_t lock;
};

extern struct honeypot_hooks_s honeypot_hooks;

#define HONEYPOT_HOOK1(hook, arg1)                  \
  do {                                              \
    read_lock(&honeypot_hooks.lock);                \
    if (honeypot_hooks.hook) {                      \
      honeypot_hooks.hook(arg1);                    \
    }                                               \
    read_unlock(&honeypot_hooks.lock);              \
  } while(0);

#define HONEYPOT_HOOK2(hook, arg1, arg2)            \
  do {                                              \
    read_lock(&honeypot_hooks.lock);                \
    if (honeypot_hooks.hook) {                      \
      honeypot_hooks.hook(arg1, arg2);                   \
    }                                               \
    read_unlock(&honeypot_hooks.lock);              \
  } while(0);

#endif // _LINUX_HONEYPOT_H

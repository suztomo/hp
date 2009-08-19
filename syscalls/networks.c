/*
  Functions that replace ip addresses in system calls.
 */
#include <linux/kernel.h>	/* We're doing kernel work */
#include <linux/syscalls.h> /* sys_close */
#include <linux/module.h>	/* Specifically, a module, */
#include <linux/moduleparam.h>	/* which will have params */
#include <linux/unistd.h>	/* The list of system calls */


#include <linux/sched.h>
#include <linux/net.h>
#include <asm/uaccess.h>


#include "syscalls.h"



/* Argument list sizes for sys_socketcall */
#define AL(x) ((x) * sizeof(unsigned long))
static const unsigned char nargs[19]={
	AL(0),AL(3),AL(3),AL(3),AL(2),AL(3),
	AL(3),AL(3),AL(4),AL(4),AL(4),AL(6),
	AL(6),AL(2),AL(5),AL(5),AL(3),AL(3),
	AL(4)
};
#undef AL

asmlinkage long (*original_sys_socketcall) (int call, unsigned long *args);

/*
  The original call does not need to be stored?
 */
asmlinkage long (*original_sys_connect) (int fd, struct sockaddr __user * uservaddr,
                                         int addrlen);

/*
asmlinkage long (*original_sys_socketcall) (int call, unsigned long *args);
asmlinkage long (*original_sys_socketcall) (int call, unsigned long *args);
*/

static void print_call_name(int call);

static long sys_connect_wrapper(int call,  unsigned long __user * args,
                                int fd, struct sockaddr __user * uservaddr,
                                int addrlen)
{
  long ret;
  printk("*** sys connect is called by %s\n", current->comm);
  ret = original_sys_socketcall(call, args);
  return ret;
}

asmlinkage long sys_socketcall_wrapper(int call, unsigned long __user * args)
{
  unsigned long a[6];
  unsigned long a0, a1;
  int err;

  if (call < 1 || call > SYS_ACCEPT4)
    return -EINVAL;

  /* copy_from_user should be SMP safe. */
  if (copy_from_user(a, args, nargs[call]))
    return -EFAULT;

  a0 = a[0];
  a1 = a[1];

  //  print_call_name(call);

  switch(call) {
  case SYS_CONNECT:
    err = sys_connect_wrapper(call, args, a0, (struct sockaddr __user *) a1, a[2]);
    break;
  default:
    // Call the original.
    err = original_sys_socketcall(call, args);
  }
  return err;
}


MAKE_REPLACE_SYSCALL(socketcall);


int replace_syscalls_networks(void)
{
  printk(KERN_INFO "replacing system calls\n");

  /*
    Replaces system call entry.
   */

  ADD_HOOK_SYS(socketcall);
  return 0;
}

int restore_syscalls_networks(void)
{
  CLEANUP_SYSCALL(socketcall);
  return 0;
}

static void print_call_name(int call)
{
  char *call_func_name = "none";

  switch(call) {
  case SYS_SOCKET:
    call_func_name = "sys_socket";
    break;
  case SYS_BIND:
    call_func_name = "sys_bind";
    break;
  case SYS_CONNECT:
    call_func_name = "sys_connect";
    break;
  case SYS_LISTEN:
    call_func_name = "sys_listen";
    break;
  case SYS_ACCEPT:
    call_func_name = "sys_accept";
    break;
  case SYS_GETSOCKNAME:
    call_func_name = "sys_getsockname";
    break;
  case SYS_SOCKETPAIR:
    call_func_name = "sys_socketpair";
    break;
  case SYS_SEND:
    call_func_name = "sys_send";
    break;
  case SYS_SENDTO:
    call_func_name = "sys_sendto";
    break;
  case SYS_RECV:
    call_func_name = "sys_recv";
    break;
  case SYS_RECVFROM:
    call_func_name = "sys_recvfrom";
    break;
  case SYS_SHUTDOWN:
    call_func_name = "sys_shutdown";
    break;
  case SYS_GETSOCKOPT:
    call_func_name = "sys_getsockopt";
    break;
  case SYS_SENDMSG:
    call_func_name = "sys_sendmsg";
    break;
  case SYS_RECVMSG:
    call_func_name = "sys_recvmsg";
    break;
  case SYS_ACCEPT4:
    call_func_name = "sys_accept4";
    break;
  default:
    call_func_name = "error?";
    break;
  }

  printk(KERN_INFO "*** socketcall[%d:%s] by %s\n",
         call, call_func_name, current->comm);
}

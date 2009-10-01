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
#include "../common.h"

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


#include <linux/mm.h>
#include <linux/init.h>

static void print_call_name(int call);

static void get_ip_port_from_sockaddr(unsigned char ip_addr[4], int *port,
                               struct sockaddr __user * vaddr)
{
  int shiftwidth = 8;
  *port = vaddr->sa_data[1] | (vaddr->sa_data[0] << shiftwidth);
  memcpy(ip_addr, vaddr->sa_data + 2, sizeof(unsigned char) * 4);
  return;
}


static int manage_afinet_connect(struct sockaddr __user * uservaddr, int addrlen,
                          struct sockaddr * copied_vaddr)
{
  int vport = 0;
  unsigned char ip_addr[4];
  int i, j,addr_is_owned;
  int to_node = -1;
  int to_port;
  int shiftwidth = 8;
  get_ip_port_from_sockaddr(ip_addr, &vport, copied_vaddr);

  debug("*** port %d.\n", vport);
  /*
    if port is 53, we do nothing.
   */
  if (vport == 53) {
    return 0;
  }

  /*
    For each existing node, checks if the ip address is owned by the node.
   */
  for (i=1; i<HP_NODE_NUM+1; i++) {
    addr_is_owned = 1;
    for (j=0; j<4; ++j) {
      if (ip_addr[j] != hp_node_ipaddr[i][j]) {
        addr_is_owned = 0;
        debug("%d[%d]: %d and %d.\n", i, j, ip_addr[j], hp_node_ipaddr[i][j]);
        break;
      }
    }
    if (addr_is_owned) {
      to_node = i;
      break;
    }

    if (hp_node_ipaddr[i][0] == 0) {
      /*
        The last entry
        The number of hp_node_ipaddr is smaller than HP_NODE_NUM.
       */
      break;
    }
  }
  if (to_node > 0) {
    to_port = hp_node_port[to_node];
    copied_vaddr->sa_data[0] = 0xff & (to_port >> shiftwidth);
    copied_vaddr->sa_data[1] = 0xff & to_port;
    debug("*** redirected to localhost:%d.\n", to_port);
  }
  /* port has two bytes length */
  copied_vaddr->sa_data[2] = 127;
  copied_vaddr->sa_data[3] = 0;
  copied_vaddr->sa_data[4] = 0;
  copied_vaddr->sa_data[5] = 1;
  if (copy_to_user(uservaddr, copied_vaddr, addrlen)) {
    return -1;
  }
  return 0;
}



static int manage_afinet_bind(struct sockaddr __user * uservaddr, int addrlen,
                          struct sockaddr * copied_vaddr)
{
  int vport = 0;
  unsigned char ip_addr[4];
  get_ip_port_from_sockaddr(ip_addr, &vport, copied_vaddr);

  debug("*** binding port %d.\n", vport);

  /* port has two bytes length */
  copied_vaddr->sa_data[2] = 127;
  copied_vaddr->sa_data[3] = 0;
  copied_vaddr->sa_data[4] = 0;
  copied_vaddr->sa_data[5] = 1;
  if (copy_to_user(uservaddr, copied_vaddr, addrlen)) {
    return -1;
  }
  return 0;
}


static long sys_bind_wrapper(int call,  unsigned long __user * args,
                                int fd, struct sockaddr __user * uservaddr,
                                int addrlen)
{
  long ret;
  struct sockaddr *copied_vaddr;
  struct sockaddr *saved_vaddr;
  char ip_port;
  char ip_addr[4];

  /* Do nothing against non-observed node */
  if (current->hp_node < 0)
    return sys_connect(fd, uservaddr, addrlen);

  copied_vaddr = kmalloc(addrlen, GFP_KERNEL);
  saved_vaddr = kmalloc(addrlen, GFP_KERNEL);
  if (copy_from_user(copied_vaddr, uservaddr, addrlen)) {
    ret =  -EFAULT;
    goto out;
  }

  memcpy(saved_vaddr, copied_vaddr, addrlen);

  switch(copied_vaddr->sa_family) {
  case AF_INET:
    ip_port = copied_vaddr->sa_data[1];
    memcpy(ip_addr, &copied_vaddr->sa_data[2], 4);
    if (manage_afinet_bind(uservaddr, addrlen, copied_vaddr)) {
      debug("Error occured when manipulating AF_INET socket\n");
    } else {
    }
    break;
  case AF_UNIX:
    /* Local */
    break;
  default:
    break;
  }
  ret = sys_bind(fd, uservaddr, addrlen);
  copy_to_user(uservaddr, saved_vaddr, addrlen);
 out:
  kfree(copied_vaddr);
  kfree(saved_vaddr);
  return ret;
}


static long sys_connect_wrapper(int call,  unsigned long __user * args,
                                int fd, struct sockaddr __user * uservaddr,
                                int addrlen)
{
  long ret;
  struct sockaddr *copied_vaddr;
  struct sockaddr *saved_vaddr;
  char ip_port;
  char ip_addr[4];

  /* Do nothing against non-observed node */
  if (current->hp_node < 0)
    return sys_connect(fd, uservaddr, addrlen);

  copied_vaddr = kmalloc(addrlen, GFP_KERNEL);
  saved_vaddr = kmalloc(addrlen, GFP_KERNEL);
  if (copy_from_user(copied_vaddr, uservaddr, addrlen)) {
    ret =  -EFAULT;
    goto out;
  }

  memcpy(saved_vaddr, copied_vaddr, addrlen);

  switch(copied_vaddr->sa_family) {
  case AF_INET:
    ip_port = copied_vaddr->sa_data[1];
    memcpy(ip_addr, &copied_vaddr->sa_data[2], 4);
    if (manage_afinet_connect(uservaddr, addrlen, copied_vaddr)) {
      debug("Error occured when manipulating AF_INET socket\n");
    } else {
    }
    break;
  case AF_UNIX:
    /* Local */
    break;
  default:
    break;
  }
  ret = sys_connect(fd, uservaddr, addrlen);
  copy_to_user(uservaddr, saved_vaddr, addrlen);
 out:
  kfree(copied_vaddr);
  kfree(saved_vaddr);
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
  case SYS_BIND:
    err = sys_bind_wrapper(call, args, a0, (struct sockaddr __user *) a1, a[2]);
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

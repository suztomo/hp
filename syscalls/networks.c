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
#include <linux/if.h>
#include <linux/in.h>

#include <linux/honeypot.h>

#include "syscalls.h"
#include "networks.h"
#include "../common.h"
#include "../sysfs/hp_message.h"

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
asmlinkage long (*original_sys_newuname) (struct new_utsname __user *name);

/*
asmlinkage long (*original_sys_socketcall) (int call, unsigned long *args);
asmlinkage long (*original_sys_socketcall) (int call, unsigned long *args);
*/


#include <linux/mm.h>
#include <linux/init.h>

static void print_call_name(int call);


#define PORT_SHIFTWIDTH 8

static void get_ip_port_from_sockaddr(unsigned char ip_addr[4], uint16_t *port,
                               struct sockaddr * vaddr)
{
  int shiftwidth = PORT_SHIFTWIDTH;
  *port = vaddr->sa_data[1] | (vaddr->sa_data[0] << shiftwidth);
  memcpy(ip_addr, vaddr->sa_data + 2, sizeof(unsigned char) * 4);
  return;
}

static void set_ip_port_to_sockaddr(unsigned char ip_addr[4], int port,
                                    struct sockaddr * vaddr)
{
  int i;
  int shiftwidth = PORT_SHIFTWIDTH;
  BUG_ON(ip_addr == NULL);

  for (i=0; i<4; ++i) {
    /* sa_data[2], sa_data[3] .. sa_data[5] */
    vaddr->sa_data[i+2] = ip_addr[i];
  }
  if (port > 0) {
    vaddr->sa_data[0] = 0xff & (port >> shiftwidth);
    vaddr->sa_data[1] = 0xff & port;
  }
}

static int manage_afinet_connect(struct sockaddr __user * uservaddr, int addrlen,
                          struct sockaddr * copied_vaddr)
{
  uint16_t vport = 0;
  unsigned char ip_addr[4];
  int i, j,addr_is_owned;
  int to_node = -1;
  int to_port = 0;
  unsigned char localhost_addr[] = {127, 0, 0, 1};
  struct hp_message *msg;

  get_ip_port_from_sockaddr(ip_addr, &vport, copied_vaddr);

  //  debug("*** port %d.\n", vport);
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

    /* notify UI part about this connection */
    debug("hp_message_connect\n");
    //    msg = hp_message_connect(to_node);
    message_server_record(msg);
  } else {
    to_port = 0;
  }
  /* Do nothing about the port when the port is 0. */
  set_ip_port_to_sockaddr(localhost_addr, to_port, copied_vaddr);
  debug("*** redirected to localhost:%d.\n", to_port);

  if (copy_to_user(uservaddr, copied_vaddr, addrlen)) {
    return -1;
  }
  return 0;
}

#define HTTP_PORT_START 300

static int manage_afinet_bind(struct sockaddr __user * uservaddr, int addrlen,
                              struct sockaddr * copied_vaddr)
{
  uint16_t vport = 0;
  unsigned char ip_addr[4];
  int to_port;
  unsigned char localhost_addr[] = {127, 0, 0, 1};
  get_ip_port_from_sockaddr(ip_addr, &vport, copied_vaddr);
  debug("*** binding port %d.\n", vport);

  /*
    Changes binding port to 30080, 30180, 30280,...,
    if the port is 80.
   */
  if (vport == 80) {
    to_port = (HTTP_PORT_START + current->hp_node) * 100 + 80;
    set_ip_port_to_sockaddr(localhost_addr, to_port, copied_vaddr);
    debug("*** redirected to localhost:%d.\n", to_port);
  }
  if (copy_to_user(uservaddr, copied_vaddr, addrlen)) {
    return -1;
  }
  return 0;
}


/*
  Asserted that the process is not observed.
 */
static long sys_bind_wrapper(int call,  unsigned long __user * args,
                                int fd, struct sockaddr __user * uservaddr,
                                int addrlen)
{
  long ret;
  struct sockaddr *copied_vaddr;
  struct sockaddr *saved_vaddr;
  char ip_port;
  char ip_addr[4];

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

/*
  Asserted that the process is not observed.
 */


static long sys_connect_wrapper(int call,  unsigned long __user * args,
                                int fd, struct sockaddr __user * uservaddr,
                                int addrlen)
{
  long ret;
  struct sockaddr *copied_vaddr;
  struct sockaddr *saved_vaddr;
  char ip_port;
  char ip_addr[4];

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

static void record_call_name(int call)
{
  char *call_func_name = "none";
  struct hp_message *msg;
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

  msg = hp_message_syscall(call_func_name);
  message_server_record(msg);
  printk(KERN_INFO "*** socketcall[%d:%s] by %s\n",
         call, call_func_name, current->comm);
}


asmlinkage long sys_socketcall_wrapper(int call, unsigned long __user * args)
{
  unsigned long a[6];
  unsigned long a0, a1;
  int err;
  struct hp_message *msg;

  /* Do nothing against non-observed node */
  if (NOT_OBSERVED()) {
    return original_sys_socketcall(call, args);
  }

  if (call < 1 || call > SYS_ACCEPT4)
    return -EINVAL;

  /* copy_from_user should be SMP safe. */
  if (copy_from_user(a, args, nargs[call]))
    return -EFAULT;

  a0 = a[0];
  a1 = a[1];



  // record_call_name(call);
  //  print_call_name(call);
  switch(call) {
  case SYS_CONNECT:
    err = sys_connect_wrapper(call, args, a0, (struct sockaddr __user *) a1, a[2]);
    msg = hp_message_syscall("connect");
    message_server_record(msg);
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

#ifdef __NR_socketcall
MAKE_REPLACE_SYSCALL(socketcall);
#endif

void modify_sockaddr_connect(struct sockaddr *addr)
{
  uint32_t vaddr;
  uint16_t vport = 0;
  unsigned char ip_addr[4];
  int to_node = -1;
  int to_port = 0;
  unsigned char localhost_addr[] = {127, 0, 0, 1};
  struct hp_message *msg;
  struct addr_map_entry *ame;

  get_ip_port_from_sockaddr(ip_addr, &vport, addr);
  //  debug("*** port %d.\n", vport);
  /*
    if port is 53 (DNS), we do nothing.
  */
  if (vport == 53) {
    return;
  }
  /*
    For each existing node, checks if the ip address is owned by the node.
  */

  vaddr = addr_from_4ints(ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3]);
  if (vaddr == addr_map_localhost) {
    ame = addr_map_entry_from_node_port(current->hp_node, vport);
  } else {
    ame = addr_map_entry_from_addr_port(vaddr, vport);
  }
  if (ame != NULL) {
    to_node = ame->hp_node;
    to_port = ame->rport;
  }
  /* Do nothing about the port when the port is 0. */
  if (to_port > 0) {
    /* notify UI part about this connection */
    debug("redirected!!!\n")
    msg = hp_message_connect(to_node, ip_addr, vport);
    message_server_record(msg);
    set_ip_port_to_sockaddr(localhost_addr, to_port, addr);
  }

  return;
}

void modify_sockaddr_bind(struct sockaddr *addr)
{
  uint16_t vport = 0;
  uint16_t rport = 0;
  unsigned char ip_addr[4];
  struct addr_map_entry *ame;
  unsigned char localhost_addr[] = {127, 0, 0, 1};
  get_ip_port_from_sockaddr(ip_addr, &vport, addr);
  ame = addr_map_entry_from_node_port(current->hp_node,
                                      vport);
  if (ame) {
    debug("Node %d; binding %d -> %d",
          current->hp_node, vport, ame->rport);
    rport = ame->rport;
    set_ip_port_to_sockaddr(localhost_addr, rport, addr);
  }
  return;
}

void hp_sys_connect_hook(struct sockaddr_storage *address, int addrlen)
{
  struct sockaddr *saddr = (struct sockaddr*)address;
  char ip_port;
  char ip_addr[4];
  struct hp_message *msg;
  if (NOT_OBSERVED()) return;

  msg = hp_message_syscall("connect");
  message_server_record(msg);
  switch(saddr->sa_family) {
  case AF_INET:
    ip_port = saddr->sa_data[1];
    memcpy(ip_addr, &saddr->sa_data[2], 4);
    modify_sockaddr_connect(saddr);
    break;
  case AF_UNIX:
    /* Local */
    break;
  default:
    debug("Unknown sa_family");
    break;
  }
  return;
}


void hp_sys_bind_hook(struct sockaddr_storage *address, int addrlen)
{
  struct sockaddr *saddr = (struct sockaddr*)address;
  if (NOT_OBSERVED()) return;
  modify_sockaddr_bind(saddr);
}

/*
  hp_inet_gifconf_hook is called when the process
  calls ioctl(SIOCGIFCONF).
 */
void hp_inet_gifconf_hook(struct ifreq *ifr)
{
  uint32_t addr_i = (*(struct sockaddr_in *)&(ifr->ifr_addr)).sin_addr.s_addr;
  int i;
  unsigned char old_addr[4];
  unsigned char c;
  int32_t hp_node = current->hp_node;
  if (NOT_OBSERVED()) return;
  for (i=0; i<4; ++i) {
    old_addr[i] = ((addr_i >> i*8)&0xFF);
  }
  addr_i = 0;
  /*
    If the addr points the real address, it replaces it
    with virtual address.
   */
  if (old_addr[0] == 133 && hp_node < HP_NODE_NUM) {
    for (i=0; i<4; ++i) {
      c = hp_node_ipaddr[current->hp_node][i];
      addr_i |= c << (8 * i);
    }
    (*(struct sockaddr_in *)&(ifr->ifr_addr)).sin_addr.s_addr = addr_i;
  }
}

/*
  hp_inet_gifconf_hook is called when the process
  calls ioctl(SIOCGIFADDR).
 */
void hp_devinet_siocgifaddr_hook(struct sockaddr_in *sin)
{
  uint addr_i = sin->sin_addr.s_addr;
  int i;
  unsigned char old_addr[4];
  unsigned char c;
  int32_t hp_node = current->hp_node;
  if (NOT_OBSERVED()) return;
  for (i=0; i<4; ++i) {
    old_addr[i] = ((addr_i >> i*8)&0xFF);
  }
  addr_i = 0;

  /*
    If the addr points the real address, it replaces it
    with virtual address.
   */
  if (old_addr[0] == 133 && hp_node < HP_NODE_NUM) {
    for (i=0; i<4; ++i) {
      c = hp_node_ipaddr[current->hp_node][i];
      addr_i |= c << (8 * i);
    }
    sin->sin_addr.s_addr = addr_i;
  }
}

int replace_syscalls_networks(void)
{
  printk(KERN_INFO "replacing system calls\n");
  /*
    Replaces system call entry.
   */

#ifdef __NR_socketcall
  ADD_HOOK_SYS(socketcall);
#endif
  write_lock(&honeypot_hooks.lock);
  honeypot_hooks.in_sys_connect = hp_sys_connect_hook;
  honeypot_hooks.in_inet_gifconf = hp_inet_gifconf_hook;
  honeypot_hooks.in_devinet_siocgifaddr = hp_devinet_siocgifaddr_hook;
  honeypot_hooks.in_sys_bind = hp_sys_bind_hook;
  write_unlock(&honeypot_hooks.lock);


  return 0;
}

struct addr_map_t addr_map;
uint32_t addr_map_localhost;

uint32_t addr_from_4ints(unsigned char a, unsigned  char b,
                         unsigned char c, unsigned  char d)
{
  return ((uint32_t)d)<<24 | ((uint32_t)c)<<16
    | ((uint32_t)b)<<8 | ((uint32_t)a);
}


struct addr_map_entry *addr_map_entry_create(int32_t hp_node, uint32_t addr,
                                             uint16_t vport, uint16_t rport)
{
  struct addr_map_entry *p = hp_alloc(sizeof(struct addr_map_entry));
  p->hp_node = hp_node;
  p->addr = addr;
  p->vport = vport;
  p->rport = rport;
  return p;
}

void add_addr_map_entry(int32_t hp_node, uint32_t addr,
                        uint16_t vport, uint16_t rport)
{
  struct addr_map_entry *ame = addr_map_entry_create(hp_node,addr,
                                                     vport, rport);
  BUG_ON(hp_node < 0 || hp_node > HP_NODE_NUM);
  write_lock(&addr_map.lock);
  addr_map.c[addr_map.size] = ame;
  addr_map.size++;
  write_unlock(&addr_map.lock);
}

int init_addr_map(void)
{
  uint32_t addr;
  rwlock_init(&addr_map.lock);
  write_lock(&addr_map.lock);
  addr_map.size = 0;
  addr = addr_map_localhost = addr_from_4ints(127, 0, 0, 1);
  write_unlock(&addr_map.lock);

  return 0;
}

void addr_map_entry_delete(struct addr_map_entry* ame)
{
  hp_free(ame);
}


struct addr_map_entry *addr_map_entry_from_addr_port(uint32_t addr,
                                                     uint16_t vport)
{
  int i;
  read_lock(&addr_map.lock);
  for (i=0; i<addr_map.size; ++i) {
    if (addr_map.c[i]->addr == addr && addr_map.c[i]->vport == vport) {
      read_unlock(&addr_map.lock);
      return addr_map.c[i];
    }
  }
  read_unlock(&addr_map.lock);
  return NULL;
}

struct addr_map_entry *addr_map_entry_from_node_port(int32_t hp_node,
                                                     uint16_t vport)
{
  int i;
  read_lock(&addr_map.lock);
  for (i=0; i<addr_map.size; ++i) {
    if (addr_map.c[i]->hp_node == hp_node && addr_map.c[i]->vport == vport) {
      read_unlock(&addr_map.lock);
      return addr_map.c[i];
    }
  }
  read_unlock(&addr_map.lock);
  return NULL;
}

int finalize_addr_map(void)
{
  int i;
  write_lock(&addr_map.lock);
  for (i=0; i<addr_map.size; ++i) {
    if (addr_map.c[i] == NULL) {
      BUG_ON(addr_map.c[i] == NULL);
      write_unlock(&addr_map.lock);
      return 1;
    }
    addr_map_entry_delete(addr_map.c[i]);
  }
  write_unlock(&addr_map.lock);
  return 0;
}


int restore_syscalls_networks(void)
{
#ifdef __NR_socketcall
  CLEANUP_SYSCALL(socketcall);
#endif
  write_lock(&honeypot_hooks.lock);
  honeypot_hooks.in_sys_connect = NULL;
  honeypot_hooks.in_inet_gifconf = NULL;
  honeypot_hooks.in_devinet_siocgifaddr = NULL;
  honeypot_hooks.in_sys_bind = NULL;
  write_unlock(&honeypot_hooks.lock);
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


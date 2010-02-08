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


#define PORT_SHIFTWIDTH 8

#define GL_ADDR_MAP_ADDR_UNUSED 0
#define GL_ADDR_MAP_PORT_UNUSED 0

static void get_ip_port_from_sockaddr(unsigned char ip_addr[4], uint16_t *port,
                               struct sockaddr * vaddr)
{
  int shiftwidth = PORT_SHIFTWIDTH;
  if (port) {
    *port = vaddr->sa_data[1] | (vaddr->sa_data[0] << shiftwidth);
  }
  if (ip_addr) {
    memcpy(ip_addr, vaddr->sa_data + 2, sizeof(unsigned char) * 4);
  }
  return;
}



static void set_ip_to_sockaddr(unsigned char ip_addr[4],
                               struct sockaddr * vaddr)
{
  int i;
  BUG_ON(ip_addr == NULL);
  for (i=0; i<4; ++i) {
    /* sa_data[2], sa_data[3] .. sa_data[5] */
    vaddr->sa_data[i+2] = ip_addr[i];
  }
}

static void set_ip_port_to_sockaddr(unsigned char ip_addr[4], int port,
                                    struct sockaddr * vaddr)
{
  int shiftwidth = PORT_SHIFTWIDTH;
  BUG_ON(port <= 0);
  set_ip_to_sockaddr(ip_addr, vaddr);
  if (port > 0) {
    vaddr->sa_data[0] = 0xff & (port >> shiftwidth);
    vaddr->sa_data[1] = 0xff & port;
  }
}

struct gl_addr_map_entry * get_gl_addr_map_entry_from_node(int32_t hp_node)
{
  int i;
  struct gl_addr_map_entry *gle;
  read_lock(&gl_addr_map.lock);
  for (i=0; i<gl_addr_map.size; ++i) {
    gle = gl_addr_map.c[i];
    if (gle->hp_node == hp_node) {
      read_unlock(&gl_addr_map.lock);
      return gle;
    }
  }
  read_unlock(&gl_addr_map.lock);
  return NULL;
}


struct gl_addr_map_entry * get_gl_addr_map_unused_entry(void)
{
  int i;
  struct gl_addr_map_entry *gle;
  read_lock(&gl_addr_map.lock);
  for (i=0; i<gl_addr_map.size; ++i) {
    gle = gl_addr_map.c[i];
    if (gle->addr == GL_ADDR_MAP_ADDR_UNUSED) {
      read_unlock(&gl_addr_map.lock);
      return gle;
    }
  }
  read_unlock(&gl_addr_map.lock);
  return NULL;
}

struct gl_addr_map_entry *gl_addr_map_entry_create(int32_t hp_node)
{
  struct gl_addr_map_entry *p = hp_alloc(sizeof(struct gl_addr_map_entry));
  p->hp_node = hp_node;
  p->addr = GL_ADDR_MAP_ADDR_UNUSED; // unused yet
  p->size = 0;
  return p;
}

struct port_map_entry* port_map_entry_create(uint16_t vport,
                                             uint32_t raddr,
                                             uint16_t rport)
{
  struct port_map_entry *p = hp_alloc(sizeof(struct port_map_entry));
  p->vport = vport;
  p->raddr = raddr; /* unused */
  p->rport = rport;
  return p;
}

struct gl_addr_map_entry* add_gl_addr_map_entry(uint32_t addr)
{
  struct gl_addr_map_entry *gle = get_gl_addr_map_unused_entry();
  struct hp_message *msg;
  if (gle == NULL) {
    debug("invalid global addr mapping");
    return NULL;
  }
  write_lock(&gl_addr_map.lock);
  gle->addr = addr;
  write_unlock(&gl_addr_map.lock);

  msg = hp_message_node_info(gle->hp_node, gle->addr);
  message_server_record(msg);

  return gle;
}

void init_gl_addr_map_entry(int32_t hp_node)
{
  struct gl_addr_map_entry *gle = gl_addr_map_entry_create(hp_node);
  write_lock(&gl_addr_map.lock);
  gl_addr_map.c[gl_addr_map.size] = gle;
  gl_addr_map.size++;
  write_unlock(&gl_addr_map.lock);
}

void init_gl_addr_map_entry_portmap(int32_t hp_node,
                                    uint16_t rport)
{
  struct port_map_entry *pmap;
  struct gl_addr_map_entry *gle;
  pmap = port_map_entry_create(GL_ADDR_MAP_PORT_UNUSED, 0, rport);
  if (pmap == NULL) {
    debug("pmap creation failed");
    return;
  }
  gle = get_gl_addr_map_entry_from_node(hp_node);
  if (gle == NULL) {
    debug("No such global address entry for %d", hp_node);
    return;
  }
  if (gle->size >= GL_ADDR_MAP_ENTRY_NUM) {
    /* too much port map in the entry (hp_node) */
    debug("too much port map in the hp_node(%d)", hp_node);
    return;
  }
  write_lock(&gl_addr_map.lock);
  gle->maps[gle->size] = pmap;
  pmap->gle = gle;
  gle->size++;
  write_unlock(&gl_addr_map.lock);

  return;
}



struct port_map_entry *
add_gl_addr_map_entry_portmap(struct gl_addr_map_entry* gle,
                                   uint16_t vport)
{
  int i;
  struct port_map_entry* pmap;
  if (gle == NULL) {
    debug("no such global addr map entry");
    return NULL;
  }
  write_lock(&gl_addr_map.lock);
  for (i=0; i<gle->size; ++i) {
    pmap = gle->maps[i];
    if (pmap->vport == GL_ADDR_MAP_PORT_UNUSED) {
      pmap->vport = vport;
      write_unlock(&gl_addr_map.lock);
      return pmap;
    }
  }
  debug("already filled %d, which has %d maps",
        gle->hp_node, gle->size);
  write_unlock(&gl_addr_map.lock);
  return NULL;
}

struct port_map_entry *port_map_entry_from_addr_port(uint32_t vaddr,
                                                           uint16_t vport)
{
  int i, j;
  struct gl_addr_map_entry *gle;
  struct port_map_entry *pmap;
  read_lock(&gl_addr_map.lock);
  for (i=0; i<gl_addr_map.size; ++i) {
    gle = gl_addr_map.c[i];
    if (gle->addr == vaddr) {
      debug("found hp_node %d (%s), which has %d maps",
            gle->hp_node, string_of_addr(vaddr), gle->size);
      for (j=0; j<gle->size; ++j) {
        pmap = gle->maps[j];
        if (pmap->vport == vport) { /* found the mapping */
          read_unlock(&gl_addr_map.lock);
          debug("found mapping node %d: %d -> %d",
                gle->hp_node, (int)(pmap->rport), (int)(pmap->vport));
          return pmap;
        }
      }
      /* not found in the node */
      read_unlock(&gl_addr_map.lock);
      return add_gl_addr_map_entry_portmap(gle, vport);
    }
  }
  read_unlock(&gl_addr_map.lock);
  debug("no such global address %s", string_of_addr(vaddr));
  gle = add_gl_addr_map_entry(vaddr);
  if (gle) {
    pmap = add_gl_addr_map_entry_portmap(gle, vport);
    return pmap;
  }
  return NULL;
}



struct port_map_entry *port_map_entry_from_node_port(int32_t hp_node,
                                                     uint16_t vport)
{
  int j;
  struct gl_addr_map_entry *gle;
  struct port_map_entry *pmap;
  gle = get_gl_addr_map_entry_from_node(hp_node);
  read_lock(&gl_addr_map.lock);
  for (j=0; j<gle->size; ++j) {
    pmap = gle->maps[j];
    if (pmap->vport == vport) { /* found the mapping */
      read_unlock(&gl_addr_map.lock);
      debug("found mapping node %d: %d -> %d",
            gle->hp_node, (int)(pmap->vport), (int)(pmap->rport));
      return pmap;
    }
  }
  read_unlock(&gl_addr_map.lock);
  return NULL;
}


static void modify_sockaddr_connect(struct sockaddr *addr)
{
  uint32_t vaddr;
  uint16_t vport = 0;
  unsigned char ip_addr[4];
  int to_node = -1;
  int to_port = 0;
  unsigned char localhost_addr[] = {127, 0, 0, 1};
  uint32_t laddr = addr_from_4ints(localhost_addr[0],
                                   localhost_addr[1],
                                   localhost_addr[2],
                                   localhost_addr[3]);
  struct hp_message *msg;
  struct addr_map_entry *ame;
  struct port_map_entry *pmap;

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
  } else if(vaddr != 0 && vaddr != laddr) {
    // this may create new port mapping entry.
    pmap = port_map_entry_from_addr_port(vaddr, vport);
    if (pmap == NULL) {
      debug("could not create new port mapping");
      return;
    }
    debug("using port mapping %s:%d (real %d)", string_of_addr(vaddr),
          pmap->vport, pmap->rport);
    to_node = pmap->gle->hp_node;
    to_port = pmap->rport;
  }
  /* Do nothing about the port when the port is 0. */
  if (to_port > 0) {
    /* notify UI part about this connection */
    msg = hp_message_connect(to_node, ip_addr, vport);
    message_server_record(msg);
    set_ip_port_to_sockaddr(localhost_addr, to_port, addr);
  }

  return;
}

static void modify_sockaddr_bind(struct sockaddr *addr)
{
  uint16_t vport = 0;
  uint16_t rport = 0;
  unsigned char ip_addr[4];
  struct addr_map_entry *ame;
  //  struct port_map_entry *pmap;
  unsigned char localhost_addr[] = {127, 0, 0, 1};
  get_ip_port_from_sockaddr(ip_addr, &vport, addr);
  ame = addr_map_entry_from_node_port(current->hp_node,
                                      vport);
  if (ame) {
    rport = ame->rport;
    set_ip_port_to_sockaddr(localhost_addr, rport, addr);
  } else {
    /* binding real port */
    //    debug("binding port %d", vport);
    /*
    pmap = port_map_entry_from_node_port(current->hp_node,
                                         rport);
    */
    //    rport = vport;
    //    set_ip_port_to_sockaddr(localhost_addr, rport, addr);
  }
  return;
}

static void modify_sockaddr_sendto(struct sockaddr *addr)
{
  unsigned char ip_addr[4];
  unsigned char localhost_addr[] = {127, 0, 0, 1};
  get_ip_port_from_sockaddr(ip_addr, NULL, addr);
  if (false) {
    set_ip_to_sockaddr(localhost_addr, addr);
  }
}

static void hp_sys_connect_hook(struct sockaddr_storage *address, int addrlen)
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


static void hp_sys_bind_hook(struct sockaddr_storage *address, int addrlen)
{
  struct sockaddr *saddr = (struct sockaddr*)address;
  if (NOT_OBSERVED()) return;
  modify_sockaddr_bind(saddr);
}

static void hp_sys_sendto_hook(struct sockaddr_storage *address, int addrlen)
{
  struct sockaddr *saddr = (struct sockaddr*)address;
  //  if (NOT_OBSERVED()) return;
  modify_sockaddr_sendto(saddr);
}

/*
  hp_inet_gifconf_hook is called when the process
  calls ioctl(SIOCGIFCONF).
 */
static void hp_inet_gifconf_hook(struct ifreq *ifr)
{
  uint32_t addr_i = (*(struct sockaddr_in *)&(ifr->ifr_addr)).sin_addr.s_addr;
  int old_addr[4];
  int32_t hp_node = current->hp_node;
  struct addr_map_entry *ame;
  if (NOT_OBSERVED()) return;
  /*
  for (i=0; i<4; ++i) {
    old_addr[i] = ((addr_i >> i*8)&0xFF);
  }
  */
  ints_from_addr(addr_i, old_addr, old_addr+1, old_addr+2, old_addr+3);
  addr_i = 0;
  /*
    If the addr points the real address, it replaces it
    with virtual address.
   */
  if (old_addr[0] == 133 && hp_node < HP_NODE_NUM) {
    // local network. Do not search global ones.
    ame = addr_map_entry_from_node(hp_node);
    if (ame == NULL) {
      debug("No such hp_node");
      return;
    }
    addr_i = ame->addr;
      /*
        for (i=0; i<4; ++i) {
      c = hp_node_ipaddr[current->hp_node][i];
      addr_i |= c << (8 * i);
    } */
    (*(struct sockaddr_in *)&(ifr->ifr_addr)).sin_addr.s_addr = addr_i;
  }
}

/*
  hp_inet_gifconf_hook is called when the process
  calls ioctl(SIOCGIFADDR).
 */
static void hp_devinet_siocgifaddr_hook(struct sockaddr_in *sin)
{
  uint addr_i = sin->sin_addr.s_addr;
  int old_addr[4];
  int32_t hp_node = current->hp_node;
  struct addr_map_entry *ame;
  if (NOT_OBSERVED()) return;
  ints_from_addr(addr_i, old_addr, old_addr+1, old_addr+2, old_addr+3);
  /*
  for (i=0; i<4; ++i) {
    old_addr[i] = ((addr_i >> i*8)&0xFF);
  }
  */

  addr_i = 0;

  /*
    If the addr points the real address, it replaces it
    with virtual address.
   */
  if (old_addr[0] == 133 && hp_node < HP_NODE_NUM) {
    ame = addr_map_entry_from_node(hp_node);
    if (ame == NULL) {
      debug("No such hp_node");
      return;
    }
    addr_i = ame->addr;
    /*
    for (i=0; i<4; ++i) {
      c = hp_node_ipaddr[current->hp_node][i];
      addr_i |= c << (8 * i);
    }
    */
    sin->sin_addr.s_addr = addr_i;
  }
}

static void hp_devinet_siocgifbrdaddr_hook(struct sockaddr_in *sin)
{
  uint addr_i;
  if (NOT_OBSERVED()) return;
  addr_i = addr_from_4ints(192, 168, 111, 1);
  sin->sin_addr.s_addr = addr_i;
}

struct addr_map_t addr_map;
struct gl_addr_map_t gl_addr_map;
uint32_t addr_map_localhost;

uint32_t addr_from_4ints(unsigned char a, unsigned  char b,
                         unsigned char c, unsigned  char d)
{
  return ((uint32_t)d)<<24 | ((uint32_t)c)<<16
    | ((uint32_t)b)<<8 | ((uint32_t)a);
}

char addr_str[16];/* 3+1+3+1+3+1+3+1 */

char *string_of_addr(uint32_t addr) {
  int nums[4];
  ints_from_addr(addr, &nums[0],&nums[1],&nums[2],&nums[3]);
  snprintf(addr_str, sizeof(addr_str), "%d.%d.%d.%d",
           nums[0],nums[1],nums[2],nums[3]);
  return addr_str;
}

void ints_from_addr(uint32_t addr,
                     int *a, int *b,
                     int *c, int *d)
{
  *a = addr & 0xFF;
  *b = (addr >> 8) & 0xFF;
  *c = (addr >> 16) & 0xFF;
  *d = (addr >> 24) & 0xFf;
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






int init_gl_addr_map(void)
{
  int32_t hp_node;
  rwlock_init(&gl_addr_map.lock);
  gl_addr_map.size = 0;
  for (hp_node = HP_GLOBAL_NODE_OFFSET;
       hp_node < HP_GLOBAL_NODE_OFFSET + HP_GL_NODE_NUM;
       ++hp_node) {
    init_gl_addr_map_entry(hp_node);
  }
  return 0;
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


void gl_addr_map_entry_delete(struct gl_addr_map_entry* gle)
{
  int i;
  struct port_map_entry *map;
  for (i=0; i<gle->size; ++i) {
    map = gle->maps[i];
    if (map) {
      hp_free(map);
    } else {
      debug("invalid maping entry");
    }
  }
  hp_free(gle);
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

struct addr_map_entry *addr_map_entry_from_node(int32_t hp_node)
{
  int i;
  struct addr_map_entry *ame;
  read_lock(&addr_map.lock);
  for (i=0; i<addr_map.size; ++i) {
    ame = addr_map.c[i];
    if (ame->hp_node == hp_node) {
      read_unlock(&addr_map.lock);
      return ame;
    }
  }
  read_unlock(&addr_map.lock);
  return NULL;
}

int finalize_gl_addr_map(void)
{
  int i;
  struct gl_addr_map_entry *gle;
  write_lock(&gl_addr_map.lock);
  for (i=0; i<gl_addr_map.size; ++i) {
    gle = gl_addr_map.c[i];
    if (gle == NULL) {
      BUG_ON(true);
      write_unlock(&gl_addr_map.lock);
      return 1;
    }
    gl_addr_map_entry_delete(gle);
  }
  write_unlock(&gl_addr_map.lock);
  return 0;
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
  honeypot_hooks.in_devinet_siocgifbrdaddr = hp_devinet_siocgifbrdaddr_hook;
  honeypot_hooks.in_sys_bind = hp_sys_bind_hook;
  honeypot_hooks.in_sys_sendto = hp_sys_sendto_hook;
  write_unlock(&honeypot_hooks.lock);
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
  honeypot_hooks.in_devinet_siocgifbrdaddr = NULL;
  honeypot_hooks.in_sys_bind = NULL;
  honeypot_hooks.in_sys_sendto = NULL;
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


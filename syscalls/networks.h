#ifndef NETWORKS
#include "../common.h"

/*
  Functions definitions that replace system calls with IP addresses.
 */

int replace_syscalls_networks(void);
int restore_syscalls_networks(void);


/*
  Address and port mapping.
  mapping like
    192.168.111.3:22  -> 127.0.0.1:13022
    192.168.111.10:80 -> 127.0.0.1:28080
  In addition to that, when a node tries to connect localhost,
    127.0.0.1:6667    -> 127.0.0.1:18667 (using current->hp_node)
 */
struct addr_map_entry{
  int32_t hp_node;
  uint32_t addr;
  uint16_t vport;
  uint16_t rport;
};

struct port_map_entry{
  uint16_t vport;
  uint32_t raddr; /* unused */
  uint16_t rport;
};

#define GL_ADDR_MAP_ENTRY_NUM 5

struct gl_addr_map_entry{
  int32_t hp_node;
  uint32_t addr; // 0 => unused
  uint32_t size;
  struct port_map_entry* maps[GL_ADDR_MAP_ENTRY_NUM];
};

struct gl_addr_map_t {
  struct gl_addr_map_entry* c[HP_GL_NODE_NUM] ;
  uint32_t size;
  rwlock_t lock;
};

struct addr_map_t{
  struct addr_map_entry* c[HP_NODE_NUM];
  uint32_t size;
  rwlock_t lock;
};


/*
  Implementation is network.c
 */

uint32_t addr_from_4ints(unsigned char a, unsigned  char b,
                         unsigned char c, unsigned  char d);


extern void add_addr_map_entry(int32_t hp_node, uint32_t addr,
                               uint16_t vport, uint16_t rport);
struct addr_map_entry *addr_map_entry_from_addr_port(uint32_t addr,
                                                     uint16_t vport);
struct addr_map_entry *addr_map_entry_from_node_port(int32_t hp_node,
                                                     uint16_t vport);
extern struct addr_map_t addr_map;
extern struct gl_addr_map_t gl_addr_map;
extern int init_addr_map(void);
extern int init_gl_addr_map(void);
extern int finalize_addr_map(void);
extern int finalize_gl_addr_map(void);

extern uint32_t addr_map_localhost;

#define NETWORKS
#endif

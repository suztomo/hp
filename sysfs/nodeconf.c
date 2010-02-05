/*
  Interfaces to change configuration of nodes.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/security.h>
#include <linux/seq_file.h>
#include <asm/uaccess.h>


#include "sysfs.h"
#include "hp_message.h"
#include "../syscalls/networks.h"


/*
  Setups node->ip relation.
  Called when a line is passed to /sys/kernel/security/hp/node_ip.
 */
ssize_t hp_nodeconf_ip_write(struct hp_io_buffer *buf)
{
  int ip_addr[4];
  unsigned char ip_addrc[4];
  int32_t hp_node;
  int vport, rport;
  int match_count;
  uint32_t addr;
  struct hp_message *msg;
  /* "<node id> <ip addr contains three dots>:<virtual port> <real port>" */
  match_count  = sscanf(buf->write_buf, "%d %d.%d.%d.%d:%d %d", &hp_node,
                        &ip_addr[0],&ip_addr[1],&ip_addr[2],&ip_addr[3],
                        &vport, &rport);
  if (match_count != 7) {
    alert(KERN_INFO "invalid arguments.\n");
  } else {
    addr = addr_from_4ints((char)0xFF&ip_addr[0], (char)0xFF&ip_addr[1],
                           (char)0xFF&ip_addr[2], (char)0xFF&ip_addr[3]);
    add_addr_map_entry(hp_node, addr, vport, rport);

    /* Notify creation of host to UI part. */
    msg = hp_message_node_info(hp_node, ip_addrc);
    message_server_record(msg);
  }
  return buf->writebuf_size;
}

/*
  Setups node->port configuration.
  Called when a line is passed to /sys/kernel/security/hp/node_port.
 */
ssize_t hp_nodeconf_port_write(struct hp_io_buffer *buf)
{
  int a, b;
  int32_t hp_node;
  uint16_t rport;
  int match_count;
  match_count  = sscanf(buf->write_buf, "%d %d", &a, &b);
  if (match_count != 2) {
    debug( "invalid arguments.\n");
  } else {
    hp_node = a;
    rport = 0xFFFF & b;
    init_gl_addr_map_entry_portmap(hp_node, rport);
    debug("port map %d of %d", rport, hp_node);
  }
  return 0;
}


/*
  Setups the buffer whose content is hp/node_ip
 */
void hp_nodeconf_ip_setup_readbuf(struct hp_io_buffer *io_buf)
{
  /* 
     0001: XXX.XXX.XXX.XXX\n (At most 23 chars)
   */
  int wrote_count = 0;
  int bufsize = 25 * HP_NODE_NUM;
  /* the buffer will be freed in release_control */
  char *buf = hp_alloc(25 * HP_NODE_NUM);
  int32_t i;
  int ipaddr[4];
  struct gl_addr_map_entry *gle;
  read_lock(&gl_addr_map.lock);
  for (i=0; i<HP_GL_NODE_NUM; ++i){
    gle = gl_addr_map.c[i];
    ints_from_addr(gle->addr, ipaddr, ipaddr+1, ipaddr+2, ipaddr+3);
    wrote_count += snprintf(buf+wrote_count, bufsize - wrote_count,
                            "%04d : %d.%d.%d.%d\n", gle->hp_node,
                            ipaddr[0],ipaddr[1],
                            ipaddr[2],ipaddr[3]);
  }
  read_unlock(&gl_addr_map.lock);
  io_buf->read_buf = buf;
  io_buf->readbuf_size = wrote_count;
}

/*
  Setups the buffer whose content is hp/node_ip
 */
void hp_nodeconf_port_setup_readbuf(struct hp_io_buffer *io_buf)
{
  /* 
     0001: 10022 -> 30033\n (At most 21 chars)
   */
  int wrote_count = 0;
  int i, j;
  int linesize = 32;
  int bufsize = linesize * HP_NODE_NUM;
  /* the buffer will be freed in release_control */
  char *buf = hp_alloc(linesize * HP_NODE_NUM);
  struct gl_addr_map_entry *gle;
  struct port_map_entry *pmap;
  read_lock(&gl_addr_map.lock);
  for (i=0; i<HP_GL_NODE_NUM; ++i){
    gle = gl_addr_map.c[i];
    for (j=0; j<gle->size; ++j) {
      pmap = gle->maps[j];
      wrote_count += snprintf(buf+wrote_count, bufsize - wrote_count,
                              "%04d : %d -> %d\n", gle->hp_node,
                              pmap->vport, pmap->rport);
    }
  }
  read_unlock(&gl_addr_map.lock);
  io_buf->read_buf = buf;
  io_buf->readbuf_size = wrote_count;
}

/*
  Setups the current process's hp_node
  Called when a line is passed to /sys/kernel/security/hp/selfconf.
 */
ssize_t hp_nodeconf_selfconf(struct hp_io_buffer *buf)
{
  int32_t hp_node;
  int match_count;
  /* "<node id>" */
  match_count  = sscanf(buf->write_buf, "%d", &hp_node);
  if (match_count != 1) {
    alert(KERN_INFO "invalid arguments.\n");
  } else {
    if (hp_node >= 0 && hp_node < HP_NODE_NUM) {
      current->hp_node = hp_node;
    }
  }
  return buf->writebuf_size;
}

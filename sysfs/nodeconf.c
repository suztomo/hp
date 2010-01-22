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
  int32_t hp_node;
  int vport, rport;
  int match_count;
  int i;
  uint32_t addr;
  struct hp_message *msg;
  /* "<node id> <ip addr contains three dots>:<virtual port> <real port>" */
  match_count  = sscanf(buf->write_buf, "%d %d.%d.%d.%d:%d %d", &hp_node,
                        &ip_addr[0],&ip_addr[1],&ip_addr[2],&ip_addr[3],
                        &vport, &rport);
  if (match_count != 7) {
    alert(KERN_INFO "invalid arguments.\n");
  } else {
    for (i=0; i<4; ++i) {
      hp_node_ipaddr[hp_node][i] = (unsigned char) (0xFF & ip_addr[i]);
    }

    addr = addr_from_4ints((char)0xFF&ip_addr[0], (char)0xFF&ip_addr[1],
                           (char)0xFF&ip_addr[2], (char)0xFF&ip_addr[3]);
    add_addr_map_entry(hp_node, addr, vport, rport);

    /* Notify creation of host to UI part. */
    msg = hp_message_node_info(hp_node, hp_node_ipaddr[hp_node]);
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
  int hp_node;
  int vport;
  int rport;
  int match_count;
  match_count  = sscanf(buf->write_buf, "%d %d %d", &hp_node,
                        &vport, &rport);
  if (match_count != 3) {
    debug( "invalid arguments.\n");
  } else {
    /* Currently vport is not used. Only ssh (22) is assigned.
       Port ranges from 0 to 2^16.
     */
    hp_node_port[hp_node] = 0xFFFF & rport;
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
  int i;
  int bufsize = 25 * HP_NODE_NUM;
  /* the buffer will be freed in release_control */
  char *buf = hp_alloc(25 * HP_NODE_NUM);
  for (i=1; i<HP_NODE_NUM+1; ++i) {
    wrote_count += snprintf(buf+wrote_count, bufsize - wrote_count,
                            "%04d : %d.%d.%d.%d\n", i,
                            hp_node_ipaddr[i][0],hp_node_ipaddr[i][1],
                            hp_node_ipaddr[i][2],hp_node_ipaddr[i][3]);
  }
  io_buf->read_buf = buf;
  io_buf->readbuf_size = wrote_count;
}

/*
  Setups the buffer whose content is hp/node_ip
 */
void hp_nodeconf_port_setup_readbuf(struct hp_io_buffer *io_buf)
{
  /* 
     0001: 10022\n (At most 12 chars)
   */
  int wrote_count = 0;
  int i;
  int linesize = 15;
  int bufsize = linesize * HP_NODE_NUM;
  /* the buffer will be freed in release_control */
  char *buf = hp_alloc(linesize * HP_NODE_NUM);
  for (i=1; i<HP_NODE_NUM+1; ++i) {
    wrote_count += snprintf(buf+wrote_count, bufsize - wrote_count,
                            "%04d : %d\n", i,
                            hp_node_port[i]);
  }
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

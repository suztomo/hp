/*
  Funcitons that manage /sys/kernel/security/hp/
 */

#include "../common.h"

#ifndef HP_SYSFS

#define HP_DIR_NAME "hp"
#define HP_DENTRY_NUM 8
#define HP_DENTRY_KEY_ROOT        0
#define HP_DENTRY_KEY_NODECONF_IP 1
#define HP_DENTRY_KEY_NODECONF_PORT 2
#define HP_DENTRY_KEY_TTY_OUTPUT 3

#define HP_TTY_OUTPUT_DIR_NAME "tty_output"
#define HP_TTY_OUTPUT_DENTRY_NUM 1000

int hp_init_sysfs(void);
int hp_cleanup_sysfs(void);

int hp_init_tty_output_sysfs(void);
int hp_cleanup_tty_output_sysfs(void);

#define HP_IOBUF_WRITE_LEN 120
#define HP_IOBUF_READ_LEN 120

extern struct dentry *hp_dentries[HP_DENTRY_NUM];

/*
  structure for honeypot interfaces between kernel and user space.
 */
struct hp_io_buffer {
  int (*read)(struct hp_io_buffer*);
  int (*write)(struct hp_io_buffer*);
  /* Exclusive lock for this structure */
  struct mutex io_sem;

  /* Buffer for read (not used) */
  char *read_buf;
  /* cursor for reading */
  int read_cur;
  /* sizeof the buffer */
  int readbuf_size;

  /* Buffer for write */
  char write_buf[HP_IOBUF_WRITE_LEN];
  /* cursor for writing */
  int write_cur;
  /* size of the buffer */
  int writebuf_size;
};

struct node_tty {
  struct list_head list;
  struct dentry *de;
};

extern struct dentry * hp_dir_entry;


int hp_nodeconf_ip_write(struct hp_io_buffer *buf);
void hp_nodeconf_ip_setup_readbuf(struct hp_io_buffer *io_buf);
int hp_nodeconf_port_write(struct hp_io_buffer *buf);
void hp_nodeconf_port_setup_readbuf(struct hp_io_buffer *io_buf);

extern int hp_tty_output_open(struct inode *inode, struct file *file);
extern ssize_t hp_tty_output_read(struct file *file, char __user *buf, size_t count,
                                  loff_t *ppos);
extern int hp_tty_output_release(struct inode *inode, struct file *file);
#define HP_SYSFS
#endif

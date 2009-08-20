/*
 * Security file system.
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/security.h>
#include <linux/seq_file.h>
#include <asm/uaccess.h>

#include "sysfs.h"

#define HP_NODE_NUM 100
#define HP_DENTRY_NUM 8
#define HP_DENTRY_KEY_ROOT        0
#define HP_DENTRY_KEY_NODECONF_IP 1

/* Initialized to NULL */
static struct dentry *hp_dentries[HP_DENTRY_NUM];


static char hp_node_ipaddr[HP_NODE_NUM+1][4];

void *hp_alloc(const size_t size)
{
  void *p = kzalloc(size, GFP_KERNEL);
  if (p) {
    
  } else {
    printk(KERN_ALERT "no mem");
  }
  return p;
}

void hp_free(const void *p)
{
  kfree(p);
}

extern int hp_node_max;


static int hp_nodeconf_ip_write(struct hp_io_buffer *buf)
{
  int ip_addr[4];
  int hp_node;
  int match_count;
  int i;
  printk(KERN_INFO "*** %s\n", buf->write_buf);
  match_count  = sscanf(buf->write_buf, "%d %d.%d.%d.%d", &hp_node,
                        &ip_addr[0],&ip_addr[1],&ip_addr[2],&ip_addr[3]);
  if (match_count != 5) {
    printk(KERN_INFO "invalid arguments.\n");
  } else {
    printk(KERN_INFO "Node:%d IP:%d.%d.%d.%d\n", hp_node,
           ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3]);
    for (i=0; i<4; ++i) {
      hp_node_ipaddr[hp_node][i] = (char ) (0xFF & ip_addr[i]);
    }
  }
  return 0;
}

static void hp_nodeconf_ip_setup_readbuf(struct hp_io_buffer *io_buf)
{
  /* 
     0001: XXX.XXX.XXX.XXX\n (23 chars)
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

static int hp_open_control(int type, struct file *file)
{
  struct hp_io_buffer *buf = hp_alloc(sizeof(struct hp_io_buffer));
  buf->writebuf_size = sizeof(buf->write_buf);
  buf->write_cur = 0;
  buf->read_cur = 0;
  mutex_init(&buf->io_sem);
  printk(KERN_INFO "*** open!!!\n");
  file->private_data = buf;
  switch(type) {
  case HP_DENTRY_KEY_NODECONF_IP:
    buf->write = hp_nodeconf_ip_write;
    hp_nodeconf_ip_setup_readbuf(buf);
    break;
  default:
    printk(KERN_INFO "invalid type in %s.\n", __func__);
  }
  return 0;
}

static int hp_open(struct inode *inode, struct file *file)
{
  const int key = ((u8 *) file->f_path.dentry->d_inode->i_private)
    -((u8 *) NULL);
  return hp_open_control(key, file);
}

static ssize_t hp_read_control(struct file *file, char __user *buf, size_t count,
                               loff_t *ppos)
{
  struct hp_io_buffer * io_buf = file->private_data;
  ssize_t to_write = count;
  if (mutex_lock_interruptible(&io_buf->io_sem)) {
    return -EINTR;
  }

  if (io_buf->read_cur >= io_buf->readbuf_size) {
    return 0;
  }
  if (to_write > io_buf->readbuf_size - io_buf->read_cur) {
    to_write = io_buf->readbuf_size - io_buf->read_cur;
  }
  if (copy_to_user(buf, io_buf->read_buf + io_buf->read_cur, to_write)) {
    return -EINVAL;
  }
  io_buf->read_cur += to_write;

  mutex_unlock(&io_buf->io_sem);
  return to_write;
}

static ssize_t hp_read(struct file *file, char __user *buf, size_t count,
                       loff_t *ppos)
{
  printk(KERN_INFO "*** read!!!\n");
  return hp_read_control(file, buf, count, ppos);
}

static int hp_release_control(struct inode *inode, struct file *file)
{
  struct hp_io_buffer *buf = file->private_data;
  if (buf->read_buf) {
    hp_free(buf->read_buf);
    buf->read_buf = NULL;
  }
  hp_free(buf);

  file->private_data = NULL;

  return 0;
}

static int hp_release(struct inode *inode, struct file *file)
{
  printk(KERN_INFO "*** release!!!\n");
  return hp_release_control(inode, file);
}

static int hp_write_control(struct file *file, const char __user *from_data,
                            size_t count, loff_t *ppos)
{
  struct hp_io_buffer *buf = file->private_data;
  int ret = count; /* error is written count as well */
  int avail_len = buf->writebuf_size;
  char c;
  char *to_data = buf->write_buf;
  int wrote_count = 0;
  if (avail_len < count) {
    return -EFAULT;
  }

  if (!buf->write) {
    return -ENOSYS;
  }

  /*
    A line must be smaller or equal than sizeof(buf->write_buf).
   */
  if (mutex_lock_interruptible(&buf->io_sem)) {
    return -EINTR;
  }
  while(buf->write_cur < avail_len && wrote_count < count) {
    if (get_user(c, from_data)) {
      ret = -EFAULT;
      break;
    }
    from_data++;
    wrote_count++;
    if (c != '\n') {
      buf->write_buf[buf->write_cur++] = c;
      continue;
    }
    /* return */
    to_data[buf->write_cur] = '\0';

    /* Call write function */
    buf->write(buf);
    buf->write_cur = 0;
  }
  mutex_unlock(&buf->io_sem);

  return ret;
}

static int hp_write(struct file *file, const char __user *buf,
                    size_t count, loff_t *ppos)
{
  printk(KERN_INFO "*** write!!! %d\n", count);
  return hp_write_control(file, buf, count, ppos);
}


static const struct file_operations hp_operations = {
  .open = hp_open,
  .release = hp_release,
  .read = hp_read,
  .write = hp_write,
};

static void hp_create_entry(const char *name, const mode_t mode,
                       struct dentry *parent, const u8 key)
{
  struct dentry *hp_file_entry;
  hp_file_entry = securityfs_create_file(name, mode, parent, ((u8 *)NULL) + key,
                         &hp_operations);

  /* save the pointer for removing */
  hp_dentries[key] = hp_file_entry;
}

static int hp_init_interfaces(void)
{
  struct dentry *hp_root = hp_dentries[HP_DENTRY_KEY_ROOT];
  if (!hp_root) {
    return -1;
  }
  hp_create_entry("node_ip", 0666, hp_root, HP_DENTRY_KEY_NODECONF_IP);

  return 0;
}

int hp_init_sysfs(void)
{
  struct dentry *hp_dir_entry = securityfs_create_dir(HP_DIR_NAME, NULL);
  memset(hp_dentries, 0x0, sizeof(hp_dentries));
  if (!hp_dir_entry) {
    printk(KERN_ALERT "failed securityfs_create_dir.\n");
  }
  if ((int)hp_dir_entry == -ENODEV) {
    printk(KERN_ALERT "securityfs is not enabled in this machine.\n");
    hp_dir_entry = NULL;
  }

  printk(KERN_INFO "\"/sys/kernel/security/%s/\" was created.\n", HP_DIR_NAME);

  hp_dentries[HP_DENTRY_KEY_ROOT] = hp_dir_entry;
  if (hp_init_interfaces()) {
    printk(KERN_INFO "created interfaces");
  }

  /* Success */
  return 0;
}

int hp_cleanup_sysfs(void)
{
  int i;
  for (i=0; i<HP_DENTRY_NUM; ++i) {
    struct dentry *de = hp_dentries[HP_DENTRY_NUM - i -1];
    if (de) {
      printk(KERN_INFO "removing.\n");
      securityfs_remove(de);
    }
  }

  printk(KERN_INFO "securityfs %s was removed.\n", HP_DIR_NAME);
  /* Succeess */
  return 0;
}

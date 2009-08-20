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

struct dentry * hp_dir_entry;



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

#define HP_NODECONF_IP 0x1

static int hp_nodeconf_ip_write(struct hp_io_buffer *buf)
{
  printk(KERN_INFO "*** %s\n", buf->write_buf);
  return 0;
}

static int hp_open_control(int type, struct file *file)
{
  struct hp_io_buffer *buf = hp_alloc(sizeof(struct hp_io_buffer));
  buf->writebuf_size = sizeof(buf->write_buf);
  buf->write_cur = 0;
  mutex_init(&buf->io_sem);
  printk(KERN_INFO "*** open!!!\n");
  file->private_data = buf;
  switch(type) {
  case HP_NODECONF_IP:
    buf->write = hp_nodeconf_ip_write;
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

static ssize_t hp_read(struct file *file, char __user *buf, size_t count,
                       loff_t *ppos)
{
  printk(KERN_INFO "*** read!!!\n");
  return 0;
}

static int hp_release_control(struct inode *inode, struct file *file)
{
  struct hp_io_buffer *head = file->private_data;
  hp_free(head);
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

    /* Call special write */
    buf->write(buf);
    buf->write_cur = 0;
  }

  return ret;
}

static int hp_write(struct file *file, const char __user *buf,
                    size_t count, loff_t *ppos)
{
  printk(KERN_INFO "*** write!!!\n");
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
  securityfs_create_file(name, mode, parent, ((u8 *)NULL) + key,
                         &hp_operations);
}

static int hp_init_interfaces(void)
{
  if (!hp_dir_entry) {
    return -1;
  }
  hp_create_entry("node_ip", 0666, hp_dir_entry, HP_NODECONF_IP);

  return 0;
}

int hp_init_sysfs(void)
{
  hp_dir_entry = securityfs_create_dir(HP_DIR_NAME, NULL);
  if (!hp_dir_entry) {
    printk(KERN_ALERT "failed securityfs_create_dir.\n");
  }
  if ((int)hp_dir_entry == -ENODEV) {
    printk(KERN_ALERT "securityfs is not enabled in this machine.\n");
    hp_dir_entry = NULL;
  }

  printk(KERN_INFO "\"/sys/kernel/security/%s/\" was created.\n", HP_DIR_NAME);

  if (hp_init_interfaces()) {
    printk(KERN_INFO "created interfaces");
  }

  /* Success */
  return 0;
}

int hp_cleanup_sysfs(void)
{
  if (hp_dir_entry) {
    securityfs_remove(hp_dir_entry);
  }

  printk(KERN_INFO "securityfs %s was removed.\n", HP_DIR_NAME);
  /* Succeess */
  return 0;
}

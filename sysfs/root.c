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

#include <linux/string.h>

#include "sysfs.h"


/* Initialized to NULL */
struct dentry *hp_dentries[HP_DENTRY_NUM];

/* Initialized to zero */
unsigned char hp_node_ipaddr[HP_NODE_NUM+1][4];
int hp_node_port[HP_NODE_NUM+1];

inline const unsigned char *file_fname(struct file *file)
{
  /* Null terminated? */
  return file->f_path.dentry->d_name.name;
}

inline const unsigned char *file_parent_dname(struct file *file)
{
  /* Null terminated? */
  return file->f_path.dentry->d_parent->d_name.name;
}

inline const unsigned char *dentry_fname(struct dentry *de)
{
  return de->d_name.name;
}

inline const unsigned char *dentry_parent_dname(struct dentry *de)
{
  return de->d_parent->d_name.name;
}


static int hp_open_control(int type, struct file *file)
{
  /*
    hp_alloc assures that the region is filled with zero.
   */
  struct hp_io_buffer *buf = hp_alloc(sizeof(struct hp_io_buffer));
  const char *fname;
  const char *dname;
  int dname_i;
  buf->writebuf_size = sizeof(buf->write_buf);
  buf->write_cur = 0;
  buf->read_cur = 0;
  mutex_init(&buf->io_sem);
  /*
    The private data field is used in hp_read_control
    to handle several special devices in an interface.
   */
  file->private_data = buf;
  switch(type) {
  case HP_DENTRY_KEY_NODECONF_IP:
    /*
      security/hp/ip_node
     */
    buf->write = hp_nodeconf_ip_write;
    hp_nodeconf_ip_setup_readbuf(buf);
    break;
  case HP_DENTRY_KEY_NODECONF_PORT:
    /*
      security/hp/ip_port
    */
    buf->write = hp_nodeconf_port_write;
    hp_nodeconf_port_setup_readbuf(buf);
    break;
  case HP_DENTRY_KEY_TTY_OUTPUT_NODE_TTY:
    /*
      security/hp/tty_output/73/pty5
     */
    /* tty_name, e.g., "pty5" */
    fname = file_fname(file);
    /* hp_node, e.g., "73" */
    dname = file_parent_dname(file);
    dname_i = simple_strtol(dname, NULL, 10);
    buf->write = NULL;
    hp_tty_output_setup_readbuf(buf, dname_i, fname);
    break;
  case HP_DENTRY_KEY_TTY_OUTPUT_ALL:
    buf->write = NULL;
    hp_tty_output_all_setup_readbuf(buf);
    buf->release = hp_tty_output_all_close;
    break;

  case HP_DENTRY_KEY_TTY_OUTPUT_SETUP:
    /*
      security/hp/
      setups security/hp/tty_output/
     */
    buf->write = NULL;
    hp_tty_output_prepare_output_files();
    /* Dummy contents */
    buf->read_buf = hp_alloc(1);
    buf->read_buf[0] = '0';
    buf->readbuf_size = 1;

    break;
  default:
    break;
  }
  return 0;
}

int hp_open(struct inode *inode, struct file *file)
{
  const int key = ((u8 *) file->f_path.dentry->d_inode->i_private)
    -((u8 *) NULL);
  return hp_open_control(key, file);
}

static ssize_t hp_read_control(struct file *file, char __user *buf,
                               size_t count, loff_t *ppos)
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
  } else {
    io_buf->read_cur += to_write;
  }


  mutex_unlock(&io_buf->io_sem);
  return to_write;
}

ssize_t hp_read(struct file *file, char __user *buf,
                       size_t count, loff_t *ppos)
{
  return hp_read_control(file, buf, count, ppos);
}

static int hp_release_control(struct inode *inode, struct file *file)
{
  struct hp_io_buffer *buf = file->private_data;
  if (buf->read_buf) {
    hp_free(buf->read_buf);
    buf->read_buf = NULL;
  }
  if (buf->release) {
    buf->release(buf);
  }
  hp_free(buf);

  file->private_data = NULL;

  return 0;
}

int hp_release(struct inode *inode, struct file *file)
{
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

int hp_write(struct file *file, const char __user *buf,
                    size_t count, loff_t *ppos)
{
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
  hp_file_entry = securityfs_create_file(name, mode, parent,
                                         ((u8 *)NULL) + key,
                                         &hp_operations);
  if (hp_file_entry && !IS_ERR(hp_file_entry)) {
    debug("Ceated %s in sysfs.\n", name);
  } else {
    alert("Failed creating %s in sysfs.\n", name);
  }
  /* save the pointer for removing */
  hp_dentries[key] = hp_file_entry;
}

void hp_create_dir_entry(const char *dirname, struct dentry *parent, const u8 key)
{
  struct dentry *de = securityfs_create_dir(dirname, parent);
  if (!de) {
    alert("cannot create %s directory.\n", dirname);
  }
  if ((int)de == -ENODEV) {
    /*
      Parent is missing
     */
    alert("securityfs is not enabled in this machine.\n");
    de = NULL;
  }
  hp_dentries[key] = de;
  return;
}

static int hp_init_interfaces(void)
{
  struct dentry *hp_root = hp_dentries[HP_DENTRY_KEY_ROOT];
  if (!hp_root || IS_ERR(hp_root)) {
    alert("Initializing security/hp seems to be failed");
    return -1;
  }
  hp_create_entry("node_ip",   0666, hp_root, HP_DENTRY_KEY_NODECONF_IP);
  hp_create_entry("node_port", 0666, hp_root, HP_DENTRY_KEY_NODECONF_PORT);
  /*
    tty output is transmitted via hp/tty_output/all
  hp_create_entry("tty_output_setup", 0444, hp_root,
                  HP_DENTRY_KEY_TTY_OUTPUT_SETUP);
  */
  hp_create_dir_entry(HP_TTY_OUTPUT_DIR_NAME, hp_root,
                      HP_DENTRY_KEY_TTY_OUTPUT);
  return 0;
}

int hp_init_sysfs(void)
{
  struct dentry *hp_dir_entry = securityfs_create_dir(HP_DIR_NAME, NULL);
  memset(hp_dentries, 0x0, sizeof(hp_dentries));

  if (IS_ERR(hp_dir_entry)) {
    alert("failed securityfs_create_dir.\n");
  }
  if ((int)hp_dir_entry == -ENODEV) {
    alert("securityfs is not enabled in this machine.\n");
    hp_dir_entry = NULL;
  }

  debug( "\"/sys/kernel/security/%s/\" was created.\n", HP_DIR_NAME);

  hp_dentries[HP_DENTRY_KEY_ROOT] = hp_dir_entry;
  if (hp_init_interfaces()) {
    debug("Failed creating interfaces");
  }

  if (hp_init_tty_output_sysfs()) {
    debug("Failed creating subdirs of tty_output");
  }

  /* Success */
  return 0;
}

int hp_cleanup_sysfs(void)
{
  int i;
  i = hp_cleanup_tty_output_sysfs();
  if (i) {
    alert("cleanup security/hp/tty_output/ failed.\n");
    return -1;
  }
  for (i=0; i<HP_DENTRY_NUM; ++i) {
    /* The root directory ('security/hp/') must be removed at last,
       that is, HP_DENTRY_KEY_ROOT must be 0.
     */
    struct dentry *de = hp_dentries[HP_DENTRY_NUM - i - 1];
    if (de) {
      debug( "removing %s.\n", dentry_fname(de));
      securityfs_remove(de);
    }
  }
  debug("securityfs %s was removed.\n", HP_DIR_NAME);
  /* Succeess */
  return 0;
}

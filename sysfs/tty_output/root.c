#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/security.h>
#include <linux/seq_file.h>
#include <asm/uaccess.h>

#include "../sysfs.h"
#include "../../tty/tty_hooks.h"

/*
  Initializes /sys/kernel/security/hp/tty_output/.
  This function must be called after hp_init_sysfs().
 */

/*
  Initialized to NULL?
 */
struct dentry *hp_tty_output_dentries[HP_TTY_OUTPUT_DENTRY_NUM];



int create_dentry_tty_output_hp_node(long int hp_node)
{
  struct dentry *parent_dir = hp_dentries[HP_DENTRY_KEY_TTY_OUTPUT];
  struct dentry *hp_node_dir;
  char dir_name[12];
  if (hp_tty_output_dentries[hp_node])
    return 0;

  if (!parent_dir) {
    alert("parent directory(tty_output) is not initialized.\n");
    return -ENODEV;
  }
  if (hp_node > HP_TTY_OUTPUT_DENTRY_NUM - 1) {
    alert("Too large hp_node number.\n");
    return -ENODEV;
  }
  /*
    Create directory name using (int)hp_node.
   */
  snprintf(dir_name, sizeof(dir_name), "%ld", hp_node);
  dir_name[sizeof(dir_name)-1] = '\0';

  /*
    Creates directory.
   */
  hp_node_dir = securityfs_create_dir(dir_name, parent_dir);
  if (!hp_node_dir) {
    alert("failed securityfs_create_dir.\n");
  }
  if ((int)hp_node_dir == -ENODEV) {
    /*
      Parent is missing
     */
    alert("securityfs is not enabled in this machine.\n");
    hp_node_dir = NULL;
  }
  hp_tty_output_dentries[hp_node] = hp_node_dir;
  return 0;
}


struct list_head node_tty_list[HP_TTY_OUTPUT_DENTRY_NUM];


/*
  The operations to show the tty outputs.
 */
static const struct file_operations hp_tty_output_operations = {
  .open = hp_tty_output_open,
  .release = hp_tty_output_release,
  .read = hp_tty_output_read,
};

/*
  Creates output file named /sys/kernel/security/hp/tty_output/32/tty33.
 */
int create_dentry_tty_output_hp_node_tty(long int hp_node, char *tty_name)
{
  int ret;
  struct dentry *parent;
  int mode = 0444;
  struct dentry *de;
  if (!hp_tty_output_dentries[hp_node]) {
    ret = create_dentry_tty_output_hp_node(hp_node);
    if (ret)
      return ret;
  }
  parent = hp_tty_output_dentries[hp_node];

  de = securityfs_create_file(tty_name, mode, parent, ((u8 *)NULL),
                              &hp_tty_output_operations);

  return 0;
}

int hp_init_tty_output_sysfs(void)
{
  struct dentry *hp_dir_entry = hp_dentries[HP_DENTRY_KEY_ROOT];
  int i;
  int flag = 0;
  if (!hp_dir_entry) {
    alert("parent directory is not initialized.");
    return -ENODEV;
  }

  for (i=0; i<HP_TTY_OUTPUT_DENTRY_NUM; ++i) {
    struct dentry *de = hp_tty_output_dentries[i];
    if (de) {
      flag = 1;
    }
    INIT_LIST_HEAD(&node_tty_list[i]);
  }
  if (flag) {
    memset(hp_tty_output_dentries, 0x0, sizeof(hp_tty_output_dentries));
  }

  return 0;
}



/*
  Finalizes /sys/kernel/security/hp/tty_output/
 */
int hp_cleanup_tty_output_sysfs(void)
{
  int i;
  /*
    Remove directories contained in the tty_output directory.
    The tty_output directory itself is unloaded by hp_cleanup_sysfs().
   */
  for (i=0; i<HP_TTY_OUTPUT_DENTRY_NUM; ++i) {
    struct dentry *de = hp_tty_output_dentries[HP_TTY_OUTPUT_DENTRY_NUM - i - 1];
    if (de) {
      debug("removing.");
      //      securityfs_remove(de);
    }
  }
  return 0;
}

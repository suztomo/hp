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

  printk(KERN_INFO "\"/sys/kernel/security/%s/\" was created", HP_DIR_NAME);

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

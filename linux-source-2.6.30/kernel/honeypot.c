/*
  Honeypot initialization

*/

#include <linux/syscalls.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/fsnotify.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/hash.h>
#include <linux/cache.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/file.h>
#include <asm/uaccess.h>
#include <linux/security.h>
#include <linux/seqlock.h>
#include <linux/swap.h>
#include <linux/bootmem.h>
#include <linux/fs_struct.h>
#include <linux/spinlock_types.h>
#include <linux/honeypot.h>

/*
  Configurable hooks for honeypot system.
  Alert!: this system also involves vulnerabilities for kernel module.
 */

static int dummy_in_proc_pid_readdir(struct tgid_iter *iter) {
  return 0;
}



struct honeypot_hooks_s honeypot_hooks = {
  .in_proc_pid_readdir = dummy_in_proc_pid_readdir,
  .lock = RW_LOCK_UNLOCKED,
};

/*
static int set_honeypot_hooks(void)
{
  rwlock_init(&honeypot_hooks.lock);
  read_lock(&honeypot_hooks.lock);
  read_unlock(&honeypot_hooks.lock);
  return 0;
}


  Won't work?
static int __init honeypot_init(void)
{
  if (set_honeypot_hooks()) {
    printk(KERN_INFO "honeypot hooks initialization failed");
  } else {
    printk(KERN_INFO "honeypot hooks initialized");
  }
  return 0;
}

__initcall(honeypot_init);
*/

EXPORT_SYMBOL(honeypot_hooks);

/*
 *  hp.c
 *
 *  Main honeypot routines.
 *  The kernel should hava appropriate hook point.
 */

/*
 * Standard in kernel modules 
 */
#include <linux/kernel.h>	/* We're doing kernel work */
#include <linux/syscalls.h> /* sys_close */
#include <linux/module.h>	/* Specifically, a module, */
#include <linux/moduleparam.h>	/* which will have params */
#include <linux/unistd.h>	/* The list of system calls */
#include <linux/proc_fs.h>
#include <linux/mm.h> /* VM_READ etc */
#include <linux/mutex.h>

/* 
 * For the current (process) structure, we need
 * this to know who the current user is. 
 */
#include <linux/sched.h>
#include <asm/uaccess.h>

#include "common.h"
#include "syscalls/syscall_hooks.h"
#include "tty/tty_hooks.h"
#include "syscalls/networks.h"
#include "proc/procfs_hack.h"
#include "sysfs/sysfs.h"


MODULE_LICENSE("GPL");


static void mark_process(void) {
  struct task_struct *task = &init_task;
  do {
    task->hp_node = -1;
    if (strcmp("apache2", task->comm) == 0) {
      debug("task->comm: %s", task->comm);
    }
  } while ((task = next_task(task)) != &init_task);
}


/* 
 * Initialize the module - replace the system call
 */
int init_module()
{
  printk(KERN_INFO "Hello, honeypot!\n");
  mark_process();

  if (init_addr_map()) {
    printk(KERN_ALERT "Initializing address map failed.\n");
  }

  if (init_message_server()) {
    printk(KERN_ALERT "Initializing message server failed.\n");
  }

  if (add_syscall_hooks()) {
    printk(KERN_ALERT "System calls replace (paths) failed.\n");
    return -1;
  };


  if (add_tty_hooks()) {
    printk(KERN_ALERT "tty hook failed.\n");
    return -1;
  };

  if (replace_syscalls_networks()) {
    printk(KERN_ALERT "System calls replace (networks) failed.\n");
    return -1;
  };

  if (init_proc_hacking()) {
    printk(KERN_ALERT "procfs hack failed.\n");
  }

  if (hp_init_sysfs()) {
    printk(KERN_ALERT "sysfs initialization failed.\n");
  }


  return 0;
}

/*
 * Cleanup - unregister the appropriate file from /proc
 */
void cleanup_module()
{
  printk(KERN_ALERT "Goodbye, honeypot!\n");

  if (remove_syscall_hooks()) {
    printk(KERN_ALERT "Systemcall restore failed.\n");
  }
  if (remove_tty_hooks()) {
    printk(KERN_ALERT "tty hooks restore failed.\n");
  }
  if (restore_syscalls_networks()) {
    printk(KERN_ALERT "Systemcall restore failed.\n");
  }
  if (cleanup_proc_hacking()) {
    printk(KERN_ALERT "procfs restoring failed.\n");
  }
  if (hp_cleanup_sysfs()) {
    printk(KERN_ALERT "cleanup sysfs %s was failed.\n", HP_DIR_NAME);
  }

  if (finalize_addr_map()) {
    printk(KERN_ALERT "finalizing address map failed.\n");
  }

  return;
}

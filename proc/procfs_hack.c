/*
 * procfs_hack.c
 * Hacks procfs (/proc/<pid>) so as to hide other hp_node processes
 * from a hp_node process.
 * The tempering uses honeypot_hooks structure implanted in
 * proc_pid_readdir() (/fs/proc/base.c).
 *
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

/* 
 * For the current (process) structure, we need
 * this to know who the current user is. 
 */
#include <linux/sched.h>
#include <asm/uaccess.h>


proc_pid_readdir_hook original_in_proc_pid_readdir;

int func_proc_pid_readdir (struct tgid_iter *iter) {
  int ret = 0;
  if (current->hp_node >= 0) {
    if (iter->task->hp_node >= 0 && iter->task->hp_node != current->hp_node) {
      printk("*** %s ", iter->task->comm);
      printk(" <- %s", current->comm);
      printk("  *** skipped! ***");
      printk("\n");
      ret = 1;
    }
  }
  return ret;
}

int init_proc_hacking(void)
{
  original_in_proc_pid_readdir = honeypot_hooks.in_proc_pid_readdir;
  honeypot_hooks.in_proc_pid_readdir = func_proc_pid_readdir;

  if (honeypot_hooks.in_proc_pid_readdir == func_proc_pid_readdir) {
    printk("proc_hacking is successfully installed\n");
  } else {
    /* some error? */
    return -1;
  }
  return 0;
}

int cleanup_proc_hacking(void)
{
  if (honeypot_hooks.in_proc_pid_readdir == func_proc_pid_readdir) {
    honeypot_hooks.in_proc_pid_readdir = original_in_proc_pid_readdir;
    printk("ended process module\n");
  } else {
    printk("Something wrong!\n");
  }
  return 0;
}

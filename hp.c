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

/* 
 * For the current (process) structure, we need
 * this to know who the current user is. 
 */
#include <linux/sched.h>
#include <asm/uaccess.h>

#include "paths.h"

MODULE_LICENSE("GPL");


/* 
 * Initialize the module - replace the system call
 */
int init_module()
{
  replace_syscalls();
  printk(KERN_ALERT "Hello, Kernel!\n");

  return 0;
}

/*
 * Cleanup - unregister the appropriate file from /proc
 */
void cleanup_module()
{
  printk(KERN_ALERT "Goodbye, Kernel!\n");
  return;
}

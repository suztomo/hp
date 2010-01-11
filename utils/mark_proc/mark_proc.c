/*
 * Standard in kernel modules 
 */
#include <linux/kernel.h>	/* We're doing kernel work */
#include <linux/syscalls.h> /* sys_close */
#include <linux/module.h>	/* Specifically, a module, */
#include <linux/moduleparam.h>	/* which will have params */
#include <linux/unistd.h>	/* The list of system calls */

#include <linux/mm.h> /* VM_READ etc */
/* #include <asm-x86/cacheflush.h>  change_page_attr */

/* 
 * For the current (process) structure, we need
 * this to know who the current user is. 
 */
#include <linux/sched.h>
#include <asm/uaccess.h>

MODULE_LICENSE("GPL");


/*
  Gets a mapping of (process id -> node id)
  The node id must greater or equal than 1.
  Fill unused entries with -1.
 */
#define PID_ARRAY_MAX 16
int pid_array[PID_ARRAY_MAX];
int pid_array_count;
module_param_array(pid_array, int, &pid_array_count, 0000);

int32_t node_array[PID_ARRAY_MAX];
int node_array_count;
module_param_array(node_array, int, &node_array_count, 0000);


/*
  Checks whether the pid is target or not.
  Returns the index of pid, if it is one of target processes,
  returns 0 otherwise.
 */
int is_target_proc(pid_t candidate_pid)
{
  int i;
  int p_i = (int)candidate_pid;

  for (i=0; i<pid_array_count; ++i) {
    if (pid_array[i] == p_i) {
      return i;
    }
  }
  /* the node_array hass 0-based index. */
  return -1;
}

int check_args(void) {
  int i;
  if (!pid_array_count) {
    printk(KERN_INFO "specify node_array and pid_array\n");
    return -1;
  }

  if (pid_array_count != node_array_count) {
    printk(KERN_INFO "Array size mismatch: pid_array and node_array\n");
    return -1;
  }

  for (i=pid_array_count; i<PID_ARRAY_MAX; ++i) {
    node_array[i] = pid_array[i] = -1;
  }
  return 0;
}

/*
  Traverse Tasks, marking to-be-traced if it is one of target processes.
*/
void mark_process(void) {
  struct task_struct *task = &init_task;
  int node_index;
  do {
    if ((node_index = is_target_proc(task->pid)) >= 0) {
      /* is_target_proc return -1 if it is not one of the targets */
      task->hp_node = node_array[node_index];
      printk(KERN_INFO "*** %s(%05d) [%03d] parent %s\n",
             task->comm, task->pid, task->hp_node, task->parent->comm);
    } else {
      task->hp_node = -1;
    }
  } while ((task = next_task(task)) != &init_task);
}

int init_module()
{
  /*
    Checks arguments passed with insmod
  */
  if (check_args() < 0) {
    printk("Invalid arguments");
    return -EINVAL;
  }
  printk(KERN_INFO "marking processes.\n");

  mark_process();

  /* Always fails */
  return -1;
}

/*
 * Cleanup - unregister the appropriate file from /proc
 */


void cleanup_module()
{
  /* cleanup never be called. */
  printk("ended markking processes.\n");
  return;
}

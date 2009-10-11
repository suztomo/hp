#include <linux/kernel.h>	/* We're doing kernel work */
#include <linux/syscalls.h> /* sys_close */
#include <linux/module.h>	/* Specifically, a module, */
#include <linux/moduleparam.h>	/* which will have params */
#include <linux/unistd.h>	/* The list of system calls */


#include <linux/sched.h>
#include <asm/uaccess.h>
#include <linux/honeypot.h>
#include <linux/file.h>
#include <linux/smp_lock.h>
#include <linux/list.h>

#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/spinlock.h>
#include "../common.h"
#include <linux/sched.h>
#include <linux/fs_struct.h>
#include <linux/types.h>
#include <linux/mount.h>
#include <linux/mnt_namespace.h>

#include <linux/fs.h>
#include <linux/honeypot.h>

#include "tty_hooks.h"
#include "../sysfs/sysfs.h"

struct tty_output_server tty_output_server;

static void record_tty_output(long int hp_node, struct tty_struct *tty,
                              long int sec, long int usec,
                              size_t size, char *buf)
{
  struct tty_output *tty_o;
  int ret;
  tty_o = kmalloc(sizeof(struct tty_output), GFP_KERNEL);
  tty_o->sec = sec;
  tty_o->usec = usec;
  tty_o->hp_node = current->hp_node;
  tty_o->size = size;
  tty_o->buf = kmalloc(size, GFP_KERNEL);
  /*
    The buffer might not end with NULL charactor.
   */
  memcpy(tty_o->buf, buf, size);
  memcpy(tty_o->tty_name, tty->name, sizeof(tty_o->tty_name));
  // Ends with NULL charactor
  tty_o->tty_name[sizeof(tty_o->tty_name) - 1] = '\0';
  write_lock(&tty_output_server.lock);
  list_add_tail(&tty_o->list, &tty_output_server.list);
  write_unlock(&tty_output_server.lock);

  ret = create_dentry_tty_output_hp_node_tty(hp_node, tty->name);
  return;
}

static void hp_do_tty_write(struct tty_struct *tty, size_t size)
{
  static long int start_sec = -1;
  static long int start_usec = 0;
  long int cur_sec = 0, cur_usec;
  struct timeval tv;


  /*
    Do nothing against unobserved processes.
   */
  if (current->hp_node < 0)
    return;

  do_gettimeofday(&tv);

  if (-1 == start_sec) {
    start_sec = tv.tv_sec - TTY_STARTTIME_GAP_SEC;
    start_usec = tv.tv_usec;
  }

  /*
    Calculate relative time from start.
   */
  if (tv.tv_usec > start_usec) {
    cur_sec = tv.tv_sec - start_sec;
    cur_usec = tv.tv_usec - start_usec;
  } else {
    // Borrowing subtraction
    cur_sec = tv.tv_sec - start_sec - 1;
    cur_usec = 1000000 + tv.tv_usec - start_usec;
  }
  record_tty_output(current->hp_node, tty, cur_sec, cur_usec, size, tty->write_buf);
}

int add_tty_hooks(void)
{
  INIT_LIST_HEAD(&tty_output_server.list);
  write_lock(&honeypot_hooks.lock);
  honeypot_hooks.in_do_tty_write = hp_do_tty_write;
  write_unlock(&honeypot_hooks.lock);
  return 0;
}

int remove_tty_hooks(void)
{
  struct tty_output *tty_o;
  int i = 0;
  struct list_head *p;
  char buf[256];
  write_lock(&honeypot_hooks.lock);
  honeypot_hooks.in_do_tty_write = NULL;
  write_unlock(&honeypot_hooks.lock);

  read_lock(&tty_output_server.lock);
  list_for_each(p, &tty_output_server.list) {
    tty_o = list_entry(p, struct tty_output, list);
    if (tty_o->size > sizeof(buf) - 1) {
      tty_o->size = sizeof(buf) - 1;
    }
    memcpy(buf, tty_o->buf, tty_o->size);
    buf[tty_o->size] = '\0';
    debug("%d: %s(%ld) %ld.%ld %s\n", i++, tty_o->tty_name, tty_o->hp_node,
          tty_o->sec, tty_o->usec, buf);
  }
  read_unlock(&tty_output_server.lock);

  write_lock(&tty_output_server.lock);
  while(!list_empty(&tty_output_server.list)) {
    tty_o = list_entry(tty_output_server.list.next, struct tty_output, list);
    list_del(&tty_o->list);
    kfree(tty_o->buf);
    kfree(tty_o);
  }
  write_unlock(&tty_output_server.lock);
  return 0;
}

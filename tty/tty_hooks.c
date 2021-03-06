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
#include <linux/wait.h>
#include <linux/mnt_namespace.h>

#include <linux/fs.h>
#include <linux/honeypot.h>

#include "tty_hooks.h"
#include "../sysfs/hp_message.h"
#include "../sysfs/sysfs.h"

struct hp_message_server message_server = {
  .list = LIST_HEAD_INIT(message_server.list),
  .lock = RW_LOCK_UNLOCKED,
};


static void record_tty_output(int32_t hp_node, struct tty_struct *tty,
                              int32_t sec, int32_t usec,
                              size_t size, char *buf)
{
  struct hp_message *msg = hp_alloc(sizeof(struct hp_message));
  msg->kind = HP_MESSAGE_TTY_OUTPUT;
  msg->c.tty_output.sec = sec;
  msg->c.tty_output.usec = usec;
  msg->c.tty_output.hp_node = current->hp_node;
  msg->c.tty_output.size = size;
  msg->c.tty_output.buf = hp_alloc(size);

  /*
    The buffer might not end with NULL charactor.
   */
  memcpy(msg->c.tty_output.buf, buf, size);
  memcpy(msg->c.tty_output.tty_name, tty->name, TTY_NAME_LEN);

  /* Ends with NULL charactor
     Actually tty_name[TTY_NAME_LEN + 1] in hp_message.h
  */
  msg->c.tty_output.tty_name[TTY_NAME_LEN] = '\0';

  message_server_record(msg);
  return;
}

static void hp_do_tty_write(struct tty_struct *tty, size_t size)
{
  static int32_t start_sec = -1;
  static int32_t start_usec = 0;
  long int cur_sec = 0, cur_usec;
  struct timeval tv;


  /*
    Do nothing against unobserved processes.
   */
  if (NOT_OBSERVED())
    return;

  do_gettimeofday(&tv);

  if (-1 == start_sec) {
    start_sec = tv.tv_sec - TTY_STARTTIME_GAP_SEC;
    start_usec = tv.tv_usec;
  }

  /*
    Calculate relative time from start.
   */
  if (tv.tv_usec >= start_usec) {
    cur_sec = tv.tv_sec - start_sec;
    cur_usec = tv.tv_usec - start_usec;
  } else {
    // Borrowing subtraction
    cur_sec = tv.tv_sec - start_sec - 1;
    cur_usec = 1000000 + tv.tv_usec - start_usec;
  }
  record_tty_output(current->hp_node, tty, cur_sec,
                    cur_usec, size, tty->write_buf);
}

static void record_tty_resize(int32_t hp_node, const char* ttyname,
                       int16_t cols, int16_t rows)
{
  struct hp_message *msg = hp_message_tty_resize(current->hp_node,
                                                 ttyname,
                                                 cols,
                                                 rows);
  message_server_record(msg);
}

void hp_tiocgwinsz_hook(char *name, struct winsize *winsize)
{
  if (NOT_OBSERVED())
    return;
  if (winsize->ws_col * winsize->ws_row) {
    record_tty_resize(current->hp_node, name,
                      winsize->ws_col, winsize->ws_row);
  }
}


int add_tty_hooks(void)
{
  write_lock(&honeypot_hooks.lock);
  honeypot_hooks.in_do_tty_write = hp_do_tty_write;
  honeypot_hooks.in_tiocgwinsz = hp_tiocgwinsz_hook;
  write_unlock(&honeypot_hooks.lock);
  return 0;
}

int remove_tty_hooks(void)
{
  struct hp_message *msg;
  write_lock(&honeypot_hooks.lock);
  honeypot_hooks.in_do_tty_write = NULL;
  honeypot_hooks.in_tiocgwinsz = NULL;
  write_unlock(&honeypot_hooks.lock);

  write_lock(&message_server.lock);
  while(!list_empty(&message_server.list)) {
    msg = list_entry(message_server.list.next, struct hp_message, list);
    list_del(&msg->list);
    delete_hp_message(msg);
  }
  write_unlock(&message_server.lock);
  return 0;
}

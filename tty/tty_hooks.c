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

#define TTY_TMPBUF_SIZE 255
static void hp_do_tty_write(struct tty_struct *tty, size_t size)
{
  char tmpbuf[TTY_TMPBUF_SIZE + 1];
  char *buf = tty->write_buf;
  /*
    Do nothing against unobserved processes.
   */
  if (current->hp_node < 0)
    return;

  debug("*** %ld (%s):", current->hp_node, current->comm);
  for(;;) {
    int s = size;
    if (s == 0) {
      break;
    }
    if (s > TTY_TMPBUF_SIZE) {
      s = TTY_TMPBUF_SIZE;
    }
    memcpy(tmpbuf, buf, s);
    tmpbuf[s] = '\0';
    debug("%s", tmpbuf);
    size -= s;
  }
  debug("\n");
}

int add_tty_hooks(void)
{
  write_lock(&honeypot_hooks.lock);
  honeypot_hooks.in_do_tty_write = hp_do_tty_write;
  write_unlock(&honeypot_hooks.lock);
  return 0;
}

int remove_tty_hooks(void)
{
  write_lock(&honeypot_hooks.lock);
  honeypot_hooks.in_do_tty_write = NULL;
  write_unlock(&honeypot_hooks.lock);
  return 0;
}

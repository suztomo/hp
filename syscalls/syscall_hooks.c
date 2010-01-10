/*
  Functions that replace system calls.
 */

#ifndef __KERNEL_SYSCALLS__
#define __KERNEL_SYSCALLS__
#endif

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

#include "syscalls.h"


#define HOMEDIR_PREFIX "/home/"
#define BACKUP_LEN 8


/*
  Prefixes to be convert.
  e.g. /home/ -> /j/00001/home/
 */
char * prefixes_list[] = {
  "/home",
  "/var",
  NULL,
};



#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/spinlock.h>
#include "../common.h"
#include <linux/sched.h>
#include <linux/fs_struct.h>
#include <linux/types.h>
#include <linux/mount.h>
#include <linux/mnt_namespace.h>

#define HP_PATH_LEN 4096

#include <linux/fs.h>
#include <linux/honeypot.h>
/*
static void modify_abspath_home(char *buf) {
  char tmp[HP_PATH_LEN];
  int wrote_count;
  wrote_count = snprintf(tmp, HP_PATH_LEN, "/j/%05ld%s", current->hp_node, buf);
  strncpy(buf, tmp, HP_PATH_LEN);
}
*/

static void prepend_prefix(char *buf) {
  char tmp[HP_PATH_LEN];
  int wrote_count;
  wrote_count = snprintf(tmp, HP_PATH_LEN, "/j/%05ld%s", current->hp_node, buf);
  strncpy(buf, tmp, HP_PATH_LEN);
}


static void convert_to_abspath(char *pathname)
{
  /* do nothing */
  return;
}

/*
  Manages path.
  1. If the path is relative one, convert it to absolute one.
  2. Modify the path if necessary.
 */
static int manage_path(char *buf, int len)
{
  int i;
  char *prefix;
  int f = 0;
  if (len <= 0)
    return len;
  convert_to_abspath(buf);

  for (i=0; (prefix = prefixes_list[i]); ++i) {
    if (strncmp(buf, prefix, strlen(prefix)) == 0) {
      //      debug("%s", buf);
      prepend_prefix(buf);
      //      debug(" -> %s\n", buf);
      f = 1;
      break;
    }
  }
  /*
  if (!f) {
    debug("passed: %s by %s\n", buf, current->comm);
  }
  */
  return len;
}

static int hp_do_getname(const char __user *filename, char *page)
{
  int retval;
  unsigned long len = PATH_MAX;

  if (!segment_eq(get_fs(), KERNEL_DS)) {
    if ((unsigned long) filename >= TASK_SIZE)
      return -EFAULT;
    if (TASK_SIZE - (unsigned long) filename < PATH_MAX)
      len = TASK_SIZE - (unsigned long) filename;
  }
  retval = strncpy_from_user(page, filename, len);
  if (current->hp_node >= 0) {
    retval = manage_path(page, retval);
  }

  if (retval > 0) {
    if (retval < len)
      return 0;
    return -ENAMETOOLONG;
  } else if (!retval)
    retval = -ENOENT;
  return retval;
}

#define JAIL_HOMEDIR_PREFIX_LEN 8

static void hp_sys_getcwd_hook(char *buf, unsigned long *len)
{
  if (current->hp_node >= 0) {
    debug("*** getcwd : %s (%lu) [%s]\n", buf, *len, current->comm);
    if (strncmp(buf, "/j/", 3) == 0) {
      if (*len <= JAIL_HOMEDIR_PREFIX_LEN && strlen(buf) < JAIL_HOMEDIR_PREFIX_LEN) {
        debug("too short buffer %s (%lu)\n", buf, *len);
      } else {
        *len -= JAIL_HOMEDIR_PREFIX_LEN;
        strncpy(buf, buf + JAIL_HOMEDIR_PREFIX_LEN, *len);
      }
      debug("***  after : %s\n", buf);
    }
  }
  return;
}


/*
  Get the path
  The return value must be freed by hp_free().
 */
char *hp_realpath_nofollow(const char *pathname)
{
  struct path path;
  char *sp = NULL;
  char *buf = hp_alloc(HP_PATH_LEN);
  int retval = 0;
  if (!buf)  {
    return NULL;
  }

  if (pathname && (retval = kern_path(pathname, 0, &path)) == 0) {
    sp = d_path(&path, buf, HP_PATH_LEN);
    path_put(&path);
    strncpy(buf, sp, HP_PATH_LEN);
  } else {
  }

  return buf;
}

#include <linux/utsname.h>

void hp_newuname_hook(struct new_utsname *utsn)
{
  int32_t hp_node;
  if (NOT_OBSERVED())
    return;
  hp_node  = current->hp_node;
  snprintf(utsn->nodename, sizeof(utsn->nodename), "host%04d", hp_node);
  return;
}


struct file *fp;
char log_file[] = "/etc/hoge.txt";

#define fp_write(f, buf, sz) (f->f_op->write(f, buf, sz, &f->f_pos))
#define WRITABLE(f) ((f)->f_op && (f)->f_op->write)

int add_syscall_hooks(void)
{
  printk(KERN_INFO "replacing system calls\n");

  /*
    Call functions that replaces system call entry.
   */
  write_lock(&honeypot_hooks.lock);
  honeypot_hooks.in_getname = hp_do_getname;
  honeypot_hooks.in_sys_getcwd = hp_sys_getcwd_hook;
  honeypot_hooks.in_newuname = hp_newuname_hook;;
  write_unlock(&honeypot_hooks.lock);

  return 0;
}

int remove_syscall_hooks(void)
{
  write_lock(&honeypot_hooks.lock);
  honeypot_hooks.in_getname = NULL;
  honeypot_hooks.in_sys_getcwd = NULL;
  honeypot_hooks.in_newuname = NULL;
  write_unlock(&honeypot_hooks.lock);

  return 0;
}

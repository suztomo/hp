/*
  Functions that replace system calls.
 */
#include <linux/kernel.h>	/* We're doing kernel work */
#include <linux/syscalls.h> /* sys_close */
#include <linux/module.h>	/* Specifically, a module, */
#include <linux/moduleparam.h>	/* which will have params */
#include <linux/unistd.h>	/* The list of system calls */


#include <linux/sched.h>
#include <asm/uaccess.h>
#include <linux/honeypot.h>

#include "syscalls.h"


#define HOMEDIR_PREFIX "/home/"
#define BACKUP_LEN 8


/*
  original calls. the system calls are stored to these variables.
 */
asmlinkage long (*original_sys_open) (const char *, int, int);
asmlinkage long (*original_sys_chdir) (const char*);
asmlinkage long (*original_sys_stat) (char *, struct __old_kernel_stat *);
asmlinkage long (*original_sys_stat64) (char *, struct stat64 *);
asmlinkage long (*original_sys_lstat64) (char *, struct stat64 *);
asmlinkage long (*original_sys_unlink) (char *);
asmlinkage long (*original_sys_ioctl) (unsigned int fd, unsigned int cmd,
                                unsigned long arg);



/*
  Replaces filename with dummy one if the filename matches HOMEDIR_PREFIX.

  | newpath
  | - 8 - | filename
  |        /home/suzuki/tako.txt
  |/j/00012/home/suzuki/tako.txt
*/

char *replace_path_if_necessary(char *filename)
{
  char filename_prefix[12];
  char tmp_buf[BACKUP_LEN+12];
  int i;
  for (i=0; i<12; i++) {
    get_user(filename_prefix[i], filename+i);
  }

  if (strncmp(filename_prefix, HOMEDIR_PREFIX, strlen(HOMEDIR_PREFIX)) != 0) {
    return NULL;
  }

  /*
    Going to replace parameter
   */
  for (i=0; i<BACKUP_LEN; ++i) {
    /* backup */
    get_user(current->hp_buf[i], filename - BACKUP_LEN + i);
  }

  snprintf(tmp_buf, 12, "/j/%05ld", current->hp_node); // 12?
  for (i=0; i<BACKUP_LEN; ++i) {
    put_user(tmp_buf[i], filename - BACKUP_LEN + i);
  }
  //  printk("new dirname %s\n", filename - BACKUP_LEN );

  return filename - BACKUP_LEN;
}


void restore_path(char *filename)
{
  int i;
  for (i=0; i<BACKUP_LEN; ++i) {
    //    printk("%c", current->hp_buf[i]);
    put_user(current->hp_buf[i], filename - BACKUP_LEN + i);
  }
}



#include <linux/sockios.h>
#include <linux/if.h>

asmlinkage long sys_ioctl_wrapper(unsigned int fd, unsigned int cmd,
                                unsigned long arg)
{
  long ret;
  struct ifreq ifr;
  int i;
  if (current->hp_node <= 0) {
    return original_sys_ioctl(fd, cmd, arg);
  }

  ret = original_sys_ioctl(fd, cmd, arg);
  /*
  if (cmd == SIOCGIFCONF) {

    if (copy_from_user(&ifr, (struct ifconf __user *)arg, sizeof(ifr))) {
      return -EFAULT;
    }
  }
  */
  if (cmd == SIOCGIFADDR) {

    if (copy_from_user(&ifr, (struct ifreq __user *)arg, sizeof(ifr))) {
      return -EFAULT;
    }
    printk("***ioctl for fd: %d cmd SIOCGIFADDR\n", fd);

    printk("*** ifr.ifr_ifrn.ifrn_name : %s\n",
           ifr.ifr_ifrn.ifrn_name);

    //    printk("*** %s\n", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
    printk("***Addr ");
    for (i=0; i<14; ++i) {
      printk("%02x.", (ifr.ifr_ifru.ifru_addr.sa_data[i]) & 0xff);
    }
    printk("\n");
    ifr.ifr_ifru.ifru_addr.sa_data[5] = (char)(current->hp_node & 0xff);
    printk("new 5th : %02x.\n", (ifr.ifr_ifru.ifru_addr.sa_data[5]));

    if (copy_to_user((struct ifreq __user *)arg, &ifr, sizeof(ifr))) {
      return -EFAULT;
    }

  } else {
    //    printk("***ioctl for fd: %d cmd %d\n", fd, cmd);
  }

  return ret;
}



asmlinkage long sys_unlink_wrapper(char *path)
{
  long ret;
  char *new_path;

  if (current->hp_node <= 0) {
    return original_sys_unlink(path);
  }

  new_path = replace_path_if_necessary(path);
  if (new_path == NULL) {
    return original_sys_unlink(path);
  }
  printk("*** unlinking file %s by %d on %ld %s: \n", path, current->pid,
         current->hp_node, current->comm);


  ret = original_sys_unlink(new_path);
  printk("*** ret: %ld\n", ret);
  restore_path(path);
  return ret;
}


asmlinkage int sys_chdir_wrapper(/* const */ char *path)
{
  int ret;
  char *new_path;

  if (current->hp_node <= 0) {
    /*
      When the current process is not our target
    */
    return original_sys_chdir(path);
  }
  new_path = replace_path_if_necessary(path);
  if (new_path == NULL) {
    return original_sys_chdir(path);
  }
  /* 
   * Call the original sys_open - otherwise, we lose
   * the ability to open files 
   */
  ret = original_sys_chdir(new_path);
  restore_path(path);
  return ret;
}
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

static void modify_abspath_home(char *buf) {
  char tmp[HP_PATH_LEN];
  int wrote_count;
  wrote_count = snprintf(tmp, 12, "/j/%05ld%s", current->hp_node, buf);
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

  if (len <= 0)
    return len;
  convert_to_abspath(buf);
  if (strncmp(buf, HOMEDIR_PREFIX, strlen(HOMEDIR_PREFIX))) {
    modify_abspath_home(buf);
  }

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
      debug("*** getname : %s (%s)\n", page, current->comm);
      retval = manage_path(page, retval);
      debug("***   after : %s (%s)\n", page, current->comm);
    }

	if (retval > 0) {
		if (retval < len)
			return 0;
		return -ENAMETOOLONG;
	} else if (!retval)
		retval = -ENOENT;
	return retval;
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

  if (0) {
    do_getname(NULL, NULL);
  }

  return buf;
}



asmlinkage int sys_open_wrapper(char *path, int flags, int mode)
{
  int ret;
  char *new_path;
  char *realpath = NULL;
  char pathname[1024];
  char c;
  int i = 0;

  if (current->hp_node <= 0) {
    /* Do nothing if it is not one of target processes */
    return original_sys_open(path, flags, mode);
  }

  /* Copies the string from user space */
  memset(pathname, 0x0, sizeof(pathname));
  do {
    get_user(c, path+i);
    pathname[i] = c;
    ++i;
  } while(c);

  debug("*** path     %s\n", pathname);

  realpath = hp_realpath_nofollow(pathname);

  debug("*** realpath %s\n", realpath);
  if (realpath) {
    hp_free(realpath);
  }

  new_path = replace_path_if_necessary(path);
  if (new_path == NULL) {
    return original_sys_open(path, flags, mode);
  }
  /* 
   * Call the original sys_open - otherwise, we lose
   * the ability to open files 
   */
  ret = original_sys_open(new_path, flags, mode);
  restore_path(path);
  return ret;
}

asmlinkage long sys_lstat64_wrapper(char *path, struct stat64 *buf)
{
  long ret;
  char *new_path;
  if (current->hp_node <= 0) {
    return original_sys_lstat64(path, buf);
  }

  new_path = replace_path_if_necessary(path);
  if (new_path == NULL) {
    return original_sys_lstat64(path, buf);
  }
  ret = original_sys_lstat64(new_path, buf);
  printk("*** replaced: %s\n", new_path);
  printk("*** return val: %ld\n", ret);
  restore_path(path);
  return ret;
}

asmlinkage long sys_stat_wrapper(char *path, struct __old_kernel_stat *buf)
{
  long ret;
  char *new_path;
  if (current->hp_node <= 0) {
    return original_sys_stat(path, buf);
  }

  printk("*** Stated file %s by %d on %ld %s: \n", path, current->pid,
         current->hp_node, current->comm);

  new_path = replace_path_if_necessary(path);
  if (new_path == NULL) {
    return original_sys_stat(path, buf);
  }
  ret = original_sys_stat(new_path, buf);
  restore_path(path);
  return ret;
}

asmlinkage long sys_stat64_wrapper(char *path, struct stat64 *buf)
{
  long ret;
  char *new_path;
  if (current->hp_node <= 0) {
    return original_sys_stat64(path, buf);
  }

  new_path = replace_path_if_necessary(path);
  if (new_path == NULL) {
    return original_sys_stat64(path, buf);
  }
  ret = original_sys_stat64(new_path, buf);
  restore_path(path);
  return ret;
}


MAKE_REPLACE_SYSCALL(open);
MAKE_REPLACE_SYSCALL(chdir);
MAKE_REPLACE_SYSCALL(stat);
MAKE_REPLACE_SYSCALL(stat64);
MAKE_REPLACE_SYSCALL(lstat64);
MAKE_REPLACE_SYSCALL(unlink);
MAKE_REPLACE_SYSCALL(ioctl);




int replace_syscalls_paths(void)
{
  printk(KERN_INFO "replacing system calls\n");

  /*
    Call functions that replaces system call entry.
   */
  /*
  ADD_HOOK_SYS(open);

  ADD_HOOK_SYS(chdir);
  ADD_HOOK_SYS(stat);
  ADD_HOOK_SYS(stat64);
  ADD_HOOK_SYS(lstat64);
  ADD_HOOK_SYS(unlink);
  ADD_HOOK_SYS(ioctl);
*/

  synchronize_rcu();
  honeypot_hooks.in_getname = hp_do_getname;

  return 0;
}

int restore_syscalls_paths(void)
{

  CLEANUP_SYSCALL(open);

  CLEANUP_SYSCALL(chdir);
  CLEANUP_SYSCALL(stat);
  CLEANUP_SYSCALL(stat64);
  CLEANUP_SYSCALL(lstat64);
  CLEANUP_SYSCALL(unlink);
  CLEANUP_SYSCALL(ioctl);

  synchronize_rcu();
  honeypot_hooks.in_getname = NULL;
  honeypot_hooks.in_sys_getcwd = NULL;

  return 0;
}

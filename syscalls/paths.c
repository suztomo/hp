/*
  Functions that replac system calls.
 */
#include <linux/kernel.h>	/* We're doing kernel work */
#include <linux/syscalls.h> /* sys_close */
#include <linux/module.h>	/* Specifically, a module, */
#include <linux/moduleparam.h>	/* which will have params */
#include <linux/unistd.h>	/* The list of system calls */


#include <linux/sched.h>
#include <asm/uaccess.h>

#define HOMEDIR_PREFIX "/home/"
#define BACKUP_LEN 8


/*
  The system call table.
  The kernel should be modified as EXPORT_SYMBOL(sys_call_table)
 */
extern void *sys_call_table[];

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
  Macro that defines functions that replaces system calls.
  This macro should be used grobal definitions.
 */

#define MAKE_REPLACE_SYSCALL(call)                              \
  static int add_hook_sys_##call(void) {                        \
    original_sys_##call = sys_call_table[__NR_##call];          \
    sys_call_table[__NR_##call] = sys_##call##_wrapper;         \
    if (sys_call_table[__NR_##call] != sys_##call##_wrapper) {  \
      return -1;                                                \
    } else {                                                    \
      printk(KERN_INFO #call " replaced successfully.\n");      \
    }                                                           \
    return 0;                                                   \
  }

/*
  Macro that calls the functions that replaces system calls.
 */
#define ADD_HOOK_SYS(call) \
  do {\
    if (add_hook_sys_##call() != 0) {                   \
      printk(KERN_INFO "add_hook_" #call " failed.\n");  \
      return -1;                                        \
    }                                                   \
  }while(0)

#define CLEANUP_SYSCALL(call)                                   \
  do {                                                          \
    if (sys_call_table[__NR_##call] != sys_##call##_wrapper) {  \
      printk(KERN_ALERT "Somebody else also played with the "); \
      printk(KERN_ALERT #call " system call\n");                  \
      printk(KERN_ALERT "The system may be left in ");          \
      printk(KERN_ALERT "an unstable state.\n");                \
    } else {                                                    \
      sys_call_table[__NR_##call] = original_sys_##call;        \
      printk(KERN_INFO "restored the " #call "system call as usual.\n");    \
    }                                                           \
  } while(0);


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

  snprintf(tmp_buf, 12, "/j/%05ld", current->hp_node);
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



asmlinkage int sys_open_wrapper(char *path, int flags, int mode)
{
  int ret;
  char *new_path;

  /* test */
  printk("*** Opened file by %d on %ld %s: %s\n", current->pid,
         current->hp_node, current->comm, path);
  return original_sys_open(path, flags, mode);



  if (current->hp_node <= 0) {
    return original_sys_open(path, flags, mode);
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

  printk("*** Lstat64ed file %s by %d on %ld %s: \n", path, current->pid,
         current->hp_node, current->comm);

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

  printk("*** Stat64ed file %s by %d on %ld %s: \n", path, current->pid,
         current->hp_node, current->comm);

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


int replace_syscalls(void)
{
  printk(KERN_INFO "replacing system calls\n");

  /*
    Call functions that replaces system call entry.
   */

  ADD_HOOK_SYS(open);
  /*
  ADD_HOOK_SYS(chdir);
  ADD_HOOK_SYS(stat);
  ADD_HOOK_SYS(stat64);
  ADD_HOOK_SYS(lstat64);
  ADD_HOOK_SYS(unlink);
  ADD_HOOK_SYS(ioctl);
  */
  return 0;
}

int restore_syscalls(void)
{

  CLEANUP_SYSCALL(open);
  /*
  CLEANUP_SYSCALL(chdir);
  CLEANUP_SYSCALL(stat);
  CLEANUP_SYSCALL(stat64);
  CLEANUP_SYSCALL(lstat64);
  CLEANUP_SYSCALL(unlink);
  CLEANUP_SYSCALL(ioctl);
  */
  return 0;
}

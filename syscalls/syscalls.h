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

/*
  The system call table.
  The kernel should be modified as EXPORT_SYMBOL(sys_call_table)
 */
extern void *sys_call_table[];

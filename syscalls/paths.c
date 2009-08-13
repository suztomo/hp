#include <linux/module.h>
#include <linux/kernel.h>

void replace_syscalls(void)
{
  printk(KERN_INFO "replacing system calls\n");
  return;
}

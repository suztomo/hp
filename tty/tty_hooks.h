/*
  Functions definitions that replace system calls with path.
 */
int add_tty_hooks(void);
int remove_tty_hooks(void);

struct tty_output {
  struct list_head list;
  /* Time when it recorded from when it started to record */
  long int sec;
  long int usec;
  /* The ID of honeypot node (current->hp_node) */
  long int hp_node;
  /* tty device name, distinguishing ttys in a honeypot node */
  char tty_name[6];
  /* The buffer size */
  size_t size;
  /* The content to be output */
  char *buf;
};

#include <linux/list.h>

struct tty_output_server {
  /* The contents of tty_output */
  struct list_head list;
  rwlock_t lock;
};

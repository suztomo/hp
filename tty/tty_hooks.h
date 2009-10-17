/*
  Functions definitions that replace system calls with path.
 */
int add_tty_hooks(void);
int remove_tty_hooks(void);

#define TTY_STARTTIME_GAP_SEC 1
#define TTY_NAME_LEN 6
struct tty_output {
  struct list_head list;
  /* Time when it recorded from when it started to record */
  long int sec;
  long int usec;
  /* The ID of honeypot node (current->hp_node) */
  long int hp_node;
  /* tty device name, distinguishing ttys in a honeypot node */
  char tty_name[TTY_NAME_LEN+1];
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

static inline void delete_tty_output(struct tty_output *tty_o) {
  kfree(tty_o->buf);
  kfree(tty_o);
}

extern struct tty_output_server tty_output_server;

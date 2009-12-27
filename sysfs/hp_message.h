#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/security.h>
#include <linux/seq_file.h>
#include <asm/uaccess.h>

#include <../../common.h>


#ifndef HP_MESSAGE
#define HP_MESSAGE 1

#define TTY_STARTTIME_GAP_SEC 1
#define TTY_NAME_LEN 6
#define SYSCALL_NAME_LEN 12

#define HP_MESSAGE_TTY_OUTPUT 1
#define HP_MESSAGE_ROOT_PRIV 2
#define HP_MESSAGE_SYSCALL 3

/*
  Accessed by msg->c.tty_output.hp_node etc.
 */
struct tty_output{
  /* Time when it recorded from when it started to record
     This might be useless... time can be archieved by viewer
   */
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

struct syscall {
  long int hp_node;
  char name[16];
};

struct root_priv {
  long int hp_node;
  size_t size;
  char *cmd;
};

struct hp_message {
  struct list_head list;
  /* type of which message it contains
     1: tty output
     2: root priviledges
     3: system call
   */
  char kind;
  union hp_message_union{
    struct tty_output tty_output;
    struct root_priv root_priv;
    struct syscall syscall;
  } c; // content
};



#include <linux/list.h>

struct hp_message_server {
  /* The contents of tty_output */
  struct list_head list;
  rwlock_t lock;
};

static inline void delete_hp_message(struct hp_message *msg) {
  BUG_ON(msg == NULL);
  switch(msg->kind) {
  case HP_MESSAGE_TTY_OUTPUT:
    if (msg->c.tty_output.buf) {
      hp_free(msg->c.tty_output.buf);
    }
    break;
  case HP_MESSAGE_ROOT_PRIV:
    if (msg->c.root_priv.cmd) {
      hp_free(msg->c.root_priv.cmd);
      break;
    }
    break;
  case HP_MESSAGE_SYSCALL:
    break;
  }
  kfree(msg);
}

extern struct hp_message_server message_server;

extern int init_message_server(void);
extern void message_server_record(struct hp_message *msg);
extern struct semaphore hp_message_wakeup_sem;
extern wait_queue_head_t hp_message_server_wait_queue;

extern struct hp_message *hp_message_syscall(const char *name);
extern struct hp_message *hp_message_root_priv(const char *cmd);

#endif

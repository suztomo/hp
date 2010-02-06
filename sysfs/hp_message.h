#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/security.h>
#include <linux/seq_file.h>
#include <asm/uaccess.h>

#include "../common.h"


#ifndef HP_MESSAGE
#define HP_MESSAGE 1

#define TTY_STARTTIME_GAP_SEC 1
#define TTY_NAME_LEN          6
#define SYSCALL_NAME_LEN      12

#define HP_MESSAGE_TTY_OUTPUT 1
#define HP_MESSAGE_ROOT_PRIV  2
#define HP_MESSAGE_SYSCALL    3
#define HP_MESSAGE_NODE_INFO   4
#define HP_MESSAGE_CONNECT    5


/*
  The way to implement new type of messages.

  - add new constant to HP_MESSAGE_* in this file
  - add enum entry for hp_message in this file
  - write allocation & initialization function of hp_message_*(someinfo);
    in hp_message.c and hp_message.h (for declaration)
  - insert the function into the code correctly.
  - functions for size and binary representation of the message
    in sysfs/tty_output/all.c
  - test the binary representation using cat /sys/<omit>/all > all.log and hexl-mode
  - add a new constant to models/HoneypotEvent
  - add a new branch to controllers/CanvasPlayer
  - write draw controllers against the event.
  - write procedure for block processor.
 */

/*
  Accessed by msg->c.tty_output.hp_node etc.
 */
struct tty_output{
  /* Time when it recorded from when it started to record
     This might be useless... time can be archieved by viewer
   */
  int32_t sec;
  int32_t usec;

  /* The ID of honeypot node (current->hp_node) */
  int32_t hp_node;

  /* tty device name, distinguishing ttys in a honeypot node */
  char tty_name[TTY_NAME_LEN+1];

  /* The buffer size */
  uint32_t size;

  /* The content to be output */
  char *buf;
};

struct syscall {
  int32_t hp_node;
  char name[16];
};

struct root_priv {
  int32_t hp_node;
  uint32_t size;
  char *cmd;
};

struct node_info {
  int32_t hp_node;
  unsigned char addr[4];
};

struct connect {
  int32_t from_node;
  int32_t to_node;
  unsigned char ip_addr[4];
  uint16_t port;
  /*  int duration; ? */
};

struct hp_message {
  struct list_head list;
  /* type of which message it contains
     1: tty output
     2: root priviledges
     3: system call
     4: node:ip infomation
     5: connection
   */
  char kind;
  union hp_message_union{
    struct tty_output tty_output;
    struct root_priv root_priv;
    struct syscall syscall;
    struct node_info node_info;
    struct connect connect;
  } c; // content
};



#include <linux/list.h>

struct hp_message_server {
  /* The contents of tty_output */
  struct list_head list;
  rwlock_t lock;
};



extern struct hp_message_server message_server;

extern int init_message_server(void);
extern void message_server_record(struct hp_message *msg);
extern struct semaphore hp_message_wakeup_sem;
extern wait_queue_head_t hp_message_server_wait_queue;

extern struct hp_message *hp_message_syscall(const char *name);
extern struct hp_message *hp_message_root_priv(const char *cmd);
extern struct hp_message *hp_message_node_info(int32_t hp_node,
                                               uint32_t addr);
extern struct hp_message *hp_message_connect(int32_t to_node,
                                             const unsigned char addr[4],
                                             uint16_t port);
extern void delete_hp_message(struct hp_message *msg);

#endif

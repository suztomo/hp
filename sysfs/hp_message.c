#include "hp_message.h"

#include "../syscalls/networks.h"

struct semaphore hp_message_wakeup_sem;
wait_queue_head_t hp_message_server_wait_queue;


/*
  Initializes hp_message, given kind.
  kind is option of HP_MESSAGE_*, defined in hp_message.h.
  The message is destroyed after the message is read from
  special devices (hp_tty_output_all_read).
 */
static inline struct hp_message *hp_message_create(char kind) {
  struct hp_message *msg;
  msg = hp_alloc(sizeof(struct hp_message));
  if (msg == NULL) {
    alert("faild to create hp_message");
    return NULL;
  }
  msg->kind = kind;
  return msg;
}

struct hp_message *hp_message_syscall(const char *name) {
  struct hp_message *msg;
  msg = hp_message_create(HP_MESSAGE_SYSCALL);
  strncpy(msg->c.syscall.name, name, sizeof(msg->c.syscall.name));
  /* Ends with null */
  msg->c.syscall.name[sizeof(msg->c.syscall.name) - 1] = '\0';
  msg->c.syscall.hp_node = current->hp_node;
  return msg;
}

struct hp_message *hp_message_root_priv(const char *cmd)
{
  const size_t s = strlen(cmd);
  struct hp_message *msg = hp_message_create(HP_MESSAGE_ROOT_PRIV);
  msg->c.root_priv.cmd = hp_alloc(s + 1);
  msg->c.root_priv.size = s + 1;
  msg->c.root_priv.hp_node = current->hp_node;
  return msg;
}

struct hp_message *hp_message_node_info(int32_t hp_node,
                                        uint32_t addr)
{
  int i;
  int addrs[4];
  struct hp_message *msg = hp_message_create(HP_MESSAGE_NODE_INFO);
  if (msg == NULL) {
    return NULL;
  }
  
  ints_from_addr(addr,
                 addrs, addrs+1, addrs+2, addrs+3);
  msg->c.node_info.hp_node = hp_node;
  for (i=0; i<4; ++i) {
    msg->c.node_info.addr[i] = (char)(0xFF&addrs[i]);
  }
  return msg;
}

struct hp_message *hp_message_connect(int32_t to_node,
                                      const unsigned char addr[4],
                                      uint16_t port)
{
  struct hp_message *msg = hp_message_create(HP_MESSAGE_CONNECT);
  int i;
  msg->c.connect.to_node = to_node;
  msg->c.connect.from_node = current->hp_node;
  for (i=0; i<4; ++i) {
    msg->c.connect.ip_addr[i] = addr[i];
  }
  msg->c.connect.port = port;
  return msg;
}

void message_server_record(struct hp_message *msg)
{
  if (msg == NULL) {
    debug("could not malloc msg");
  }
  write_lock(&message_server.lock);
  list_add_tail(&msg->list, &message_server.list);
  write_unlock(&message_server.lock);

  if (down_interruptible(&hp_message_wakeup_sem)) {
    alert("failed to aquire semaphore\n");
  }
  /* counterpart: wait_for_tty_output():sysfs/tty_output/all.c */
  wake_up_interruptible(&hp_message_server_wait_queue);
  up(&hp_message_wakeup_sem);
}

int init_message_server(void)
{
  sema_init(&hp_message_wakeup_sem, 1);
  INIT_LIST_HEAD(&message_server.list);
  rwlock_init(&message_server.lock);
  return 0;
}

void delete_hp_message(struct hp_message *msg) {
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
    }
    break;
  default: /* normal message need not free its own buffer */
    break;
  }
  hp_free(msg);
}


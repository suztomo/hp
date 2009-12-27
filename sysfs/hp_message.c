#include "hp_message.h"

struct semaphore hp_message_wakeup_sem;
wait_queue_head_t hp_message_server_wait_queue;


/*
  Initializes hp_message, given kind.
  kind is option of HP_MESSAGE_*, defined in hp_message.h.
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

void message_server_record(struct hp_message *msg)
{
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

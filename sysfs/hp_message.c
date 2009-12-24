#include "hp_message.h"

struct semaphore hp_message_wakeup_sem;
wait_queue_head_t hp_message_server_wait_queue;

void message_server_record(struct hp_message *msg) {
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

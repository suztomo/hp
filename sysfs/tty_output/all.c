/*
  Interfaces that pass all tty output in it.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/security.h>
#include <linux/seq_file.h>
#include <linux/wait.h>
#include <asm/uaccess.h>


#include "../sysfs.h"
#include "../../tty/tty_hooks.h"

/*
  Mutex that assures that one process can access tty_output/all at a time.
 */
DEFINE_MUTEX(hp_tty_output_all_mutex);

char *tty_output_left;
size_t tty_output_left_size = 0;

static inline size_t buffer_size_from_tty_output(struct hp_message *msg)
{
  return sizeof(char) + sizeof(size_t) + sizeof(msg->c.tty_output.hp_node)
    + sizeof(msg->c.tty_output.tty_name) +
    sizeof(msg->c.tty_output.sec) + sizeof(msg->c.tty_output.usec)
    + sizeof(size_t) + msg->c.tty_output.size;
}

static inline size_t buffer_size_from_root_priv(struct hp_message* msg) {
  return sizeof(char) + sizeof(size_t) + sizeof(msg->c.root_priv.hp_node) +
    msg->c.root_priv.size;
}

static inline size_t buffer_size_from_syscall(struct hp_message* msg) {
  return sizeof(char) + sizeof(size_t)+ sizeof(msg->c.syscall.hp_node) +
    sizeof(msg->c.syscall.name);
}

static inline size_t buffer_size_from_node_info(struct hp_message *msg) {
  return sizeof(char) + sizeof(size_t) + sizeof(msg->c.node_info.hp_node) +
    sizeof(msg->c.node_info.addr);
}

static inline size_t buffer_size_from_connect(struct hp_message *msg) {
  return sizeof(char) + sizeof(size_t) + sizeof(msg->c.connect.from_node) +
    sizeof(msg->c.connect.to_node);
}

static inline size_t buffer_size_from_hp_message(struct hp_message *msg)
{
  switch(msg->kind) {
  case HP_MESSAGE_TTY_OUTPUT:
    return buffer_size_from_tty_output(msg);
  case HP_MESSAGE_ROOT_PRIV:
    return buffer_size_from_root_priv(msg);
  case HP_MESSAGE_SYSCALL:
    return buffer_size_from_syscall(msg);
  case HP_MESSAGE_NODE_INFO:
    return buffer_size_from_node_info(msg);
  case HP_MESSAGE_CONNECT:
    return buffer_size_from_connect(msg);
  default:
    debug("invalid kind / %s", __func__);
    BUG_ON(true);
    return 0;
  }
}


/*
  Manipulates the buffer along syscall message and
  returnsp the size written to the buffer.

  |?|  size   | hp_node |  call name      |
  |1|    4    |    4    |      16         |
 */
static size_t manipulate_buffer_by_syscall(char *buf,
                                           struct hp_message *msg)
{
  char *buf_kind = buf;
  uint32_t *buf_size = (uint32_t*)(buf_kind + 1);
  int32_t *buf_hp_node = (int32_t*)(buf_size+1);
  char *buf_name = (char*)(buf_hp_node + 1);
  BUG_ON(msg->kind != HP_MESSAGE_SYSCALL);
  *buf_kind = msg->kind;
  *buf_size = (uint32_t)(sizeof(msg->c.syscall.hp_node)
                        + sizeof(msg->c.syscall.name));
  *buf_hp_node = msg->c.syscall.hp_node;
  memcpy(buf_name, msg->c.syscall.name, sizeof(msg->c.syscall.name));
  BUILD_BUG_ON(sizeof(msg->c.syscall.hp_node) + sizeof(msg->c.syscall.name) != 20);
  return buffer_size_from_syscall(msg);
}

static size_t manipulate_buffer_by_node_info(char *buf,
                                             struct hp_message *msg)
{
  char *buf_kind = buf;
  uint32_t *buf_size = (uint32_t*)(buf_kind + 1);
  int32_t *buf_hp_node = (int32_t*)(buf_size+1);
  unsigned char *buf_addr = (unsigned char *)(buf_hp_node + 1);
  *buf_kind = msg->kind;
  *buf_size = (uint32_t)(sizeof(msg->c.node_info.hp_node)
                         + sizeof(msg->c.node_info.addr));
  *buf_hp_node = msg->c.node_info.hp_node;
  memcpy(buf_addr, msg->c.node_info.addr, sizeof(msg->c.node_info.addr));
  BUILD_BUG_ON(sizeof(msg->c.node_info.hp_node) + sizeof(msg->c.node_info.addr) != 8);
  return buffer_size_from_node_info(msg);
}

static size_t manipulate_buffer_by_connect(char *buf,
                                           struct hp_message *msg)
{
  char *buf_kind = buf;
  uint32_t *buf_size = (uint32_t*)(buf_kind + 1);
  int32_t *buf_from_node = (int32_t*)(buf_size+1);
  uint32_t *buf_to_node = buf_from_node + 1;
  *buf_kind = msg->kind;
  *buf_size = (uint32_t)(sizeof(msg->c.connect.to_node)
                         + sizeof(msg->c.connect.from_node));
  *buf_from_node = msg->c.connect.from_node;
  *buf_to_node = msg->c.connect.to_node;
  BUILD_BUG_ON(sizeof(msg->c.connect.to_node) + sizeof(msg->c.connect.from_node) != 8);
  return buffer_size_from_connect(msg);
}

/*
  Manipulates the buffer along tty_output.
  Return the size written to the buffer.

  |?|  size   | hp_node | tty_name |  sec  |  usec |  size |  buffer    ...
  |1|    4    |    4    |     7    |   4   |   4   |   4   |  hogehogefugafuga ...

  the first byte of the message is the kind of the message.
  Currently only tty message is implemented.

 */
static size_t manipulate_buffer_by_tty_output(char *buf,
                                              struct hp_message *msg)
{
  struct tty_output *tty_o = &(msg->c.tty_output);
  char *buf_kind = buf;
  uint32_t *buf_size = (uint32_t*)(buf_kind + 1);
  int32_t *buf_hp_node = (int32_t*)(buf_size + 1);
  char *buf_tty_name = (char *)(buf_hp_node + 1);
  int32_t *buf_ip = (int32_t*)(buf_tty_name + sizeof(tty_o->tty_name));
  uint32_t *buf_sp = (uint32_t*)(buf_ip + 2);
  char *buf_data = (char*)(buf_sp + 1);
  BUG_ON(msg->kind != HP_MESSAGE_TTY_OUTPUT);
  *buf_kind = msg->kind;
  *buf_size = tty_o->size + 4*4 + 7;
  *buf_hp_node = tty_o->hp_node;
  memcpy(buf_tty_name, tty_o->tty_name, sizeof(tty_o->tty_name));
  *buf_ip = tty_o->sec;
  *(buf_ip+1) = tty_o->usec;
  *buf_sp = tty_o->size;
  memcpy(buf_data, tty_o->buf, tty_o->size);
  /*
    Asserts if.
   */
  BUILD_BUG_ON((sizeof(char) + sizeof(tty_o->size) + sizeof(tty_o->hp_node)
                + 2 * sizeof(tty_o->sec) +
                sizeof(tty_o->tty_name) + sizeof(tty_o->size) != 28));
  return buffer_size_from_tty_output(msg);
}


static size_t manipulate_buffer_by_root_priv(char *buf,
                                             struct hp_message *msg)
{
  /* not implemented */
  BUG_ON(true);
  return 0;
}


static size_t manipulate_buffer_by_hp_message(char *buf,
                                              struct hp_message *msg)
{
  switch(msg->kind) {
  case HP_MESSAGE_TTY_OUTPUT:
    return manipulate_buffer_by_tty_output(buf, msg);
  case HP_MESSAGE_ROOT_PRIV:
    return manipulate_buffer_by_root_priv(buf, msg);
  case HP_MESSAGE_SYSCALL:
    return manipulate_buffer_by_syscall(buf, msg);
  case HP_MESSAGE_NODE_INFO:
    return manipulate_buffer_by_node_info(buf, msg);
  case HP_MESSAGE_CONNECT:
    return manipulate_buffer_by_connect(buf, msg);
  default:
    alert("Invalid msg->kind");
    BUG_ON(true);
    return -1;
  }
}



/*
  Read handler for tty_output.
  This is not currently used because hp_tty_output_setup_readbuf() does
  initial preparation for reading buffer.

  The read must be called with big _count_.
  The process on the tty_output object should not be divided among
  the objects.
 */



static inline int msg_server_empty(struct hp_message_server *server)
{
  int ret;
  read_lock(&server->lock);
  ret = list_empty(&server->list);
  read_unlock(&server->lock);
  return ret;
}

static int wait_for_tty_output(void)
{
  int error;
  for(;;) {
    /*
      Wait until message_server is not empty.
      If the server has entry, it notifies it by wake_up().
     */
    error = wait_event_interruptible(hp_message_server_wait_queue,
                                     !msg_server_empty(&message_server));
    if (error)
      debug("error when waiting %d\n", error);
    break;
  }
  return error;
}


ssize_t hp_tty_output_all_read(struct hp_io_buffer *io_buf,
                               struct file *file, char __user *ubuf,
                            size_t count, loff_t *ppos)
{
  size_t to_write = 0;
  size_t s;
  struct hp_message *msg;
  int element_count = 0;
  int i;
  int wrote_count = 0;
  char *buf;
  int ret;
  int error;
  /*
    Wait if the list is empty, until the condition become true.
   */
  //  debug("wait for tty_output\n");
  if (msg_server_empty(&message_server) && (file->f_flags & O_NONBLOCK)) {
    ret = -EAGAIN;
    goto out;
  }
  error = wait_for_tty_output();
  //  debug("after waiting tty_output\n");
  if (error) {
    ret = error;
    goto out;
  }

  list_for_each_entry(msg, &message_server.list, list) {
    s = buffer_size_from_hp_message(msg);
    if (to_write + s > count) {
      break;
    }
    element_count += 1;
    to_write += s;
  }
  if (element_count == 0) {
    BUG_ON(true);
    debug("no eleement is left\n");
    ret = -EINVAL;
    goto out;
  }

  buf = hp_alloc(to_write);
  write_lock(&message_server.lock);

  for (i=0; i<element_count; ++i) {
    msg = list_entry(message_server.list.next, struct hp_message,
                       list);
    s = manipulate_buffer_by_hp_message(buf + wrote_count, msg);
    wrote_count += s;

    list_del(&msg->list);
    delete_hp_message(msg);
  }
  write_unlock(&message_server.lock);
  
  if (copy_to_user(ubuf, buf, wrote_count)) {
    kfree(buf);
    ret = -EBADF;
    goto out_free;
  } else {
    *ppos += wrote_count;
  }
  ret = wrote_count;

 out_free:
  //  debug("going to free buffer\n");
  kfree(buf);
 out:
  //  debug("out of hp_tty_output_all_read\n");
  return ret;
}






/*
  The operations to show the tty outputs.
 */
static const struct file_operations hp_tty_output_operations = {
  .open = hp_open,
  .release = hp_release,
  .read = hp_read,
  .write = hp_write
};


/*
  Creates hp/tty_output/all, registering appropriate
  file_operations to the file.
 */
int hp_tty_output_create_tty_output_all(struct dentry *parent)
{
  struct dentry *tty_output_all;

  /* Initializes wait queue, the declation is /sysfs/hp_message.c */
  init_waitqueue_head(&hp_message_server_wait_queue);
  tty_output_all = hp_create_tty_entry(HP_TTY_OUTPUT_ALL_NAME,
                                       0444, parent,
                                       HP_DENTRY_KEY_TTY_OUTPUT_ALL);
  if (IS_ERR(tty_output_all)) {
    alert("Error creating tty_output/" HP_TTY_OUTPUT_ALL_NAME ".");
  } else {
    hp_dentries[HP_DENTRY_KEY_TTY_OUTPUT_ALL] = tty_output_all;
  }
  mutex_init(&hp_tty_output_all_mutex);
  return 0;
}



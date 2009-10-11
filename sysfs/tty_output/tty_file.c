/*
  Interfaces to change configuration of nodes.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/security.h>
#include <linux/seq_file.h>
#include <asm/uaccess.h>


#include "../sysfs.h"
#include "../../tty/tty_hooks.h"


struct output_buf {
  struct list_head list;
  struct tty_output *tty_output;
};

inline size_t buffer_size_from_output(struct output_buf *opb)
{
  return sizeof(opb->tty_output->sec) + sizeof(opb->tty_output->usec) +
    sizeof(size_t) + opb->tty_output->size;
}
#include <linux/kernel.h>

size_t manipulate_buffer_from_output(char *buf, struct output_buf *opb)
{
  long int *buf_ip = (long int*)buf;
  size_t *buf_sp = (size_t *)(buf + 2 * sizeof(long int));
  struct tty_output *tty_o = opb->tty_output;
  *buf_ip = tty_o->sec;
  *(buf_ip+1) = tty_o->usec;
  *buf_sp = tty_o->size;
  memcpy(buf + 2 * sizeof(long int) + sizeof(size_t), tty_o->buf, tty_o->size);
  debug("buffer offset %d\n", 2 * sizeof(long int) + sizeof(size_t));
  /*
    Asserts that (2 * sizeof(long int) + sizeof(size_t) == 12)
   */
  BUILD_BUG_ON(!(2 * sizeof(long int) + sizeof(size_t) == 12));
  return buffer_size_from_output(opb);
}

/*
  Setups a buffer for a read system call to "/tty_output/<hp_node>/<tty_name>".
  This function is invoked when open system call is invoked agait the files.
 */
void hp_tty_output_setup_readbuf(struct hp_io_buffer *io_buf,
                                 long int hp_node,
                                 const char *file_fname)
{
  int wrote_count = 0;
  struct tty_output *tty_o;
  char *buf;
  size_t bufsize = 0;
  struct list_head output_buf_list;
  struct output_buf * opb;
  size_t s;
  INIT_LIST_HEAD(&output_buf_list);
  debug("Setting up %ld/%s.\n", hp_node, file_fname);
  read_lock(&tty_output_server.lock);
  list_for_each_entry(tty_o, &tty_output_server.list, list) {
    if (hp_node == tty_o->hp_node &&
        strcmp(tty_o->tty_name, file_fname) == 0) {
      opb = hp_alloc(sizeof(struct output_buf));
      opb->tty_output = tty_o;
      bufsize += buffer_size_from_output(opb);
      list_add_tail(&opb->list, &output_buf_list);
    }
  }

  /*
    The buffer is freed by hp_release_control()
   */
  buf = hp_alloc(bufsize);

  /*
    Frees the list elements
   */
  while(!list_empty(&output_buf_list)) {
    opb = list_entry(output_buf_list.next, struct output_buf, list);
    s = manipulate_buffer_from_output(buf + wrote_count, opb);
    wrote_count += s;
    list_del(&opb->list);
    kfree(opb);
  }
  read_unlock(&tty_output_server.lock);

  /*
    the buffer will be freed in release_control
    the buffer is configured properly as partty.org
    file definitions.
   */
  io_buf->read_buf = buf;
  io_buf->readbuf_size = wrote_count;
  return;
}

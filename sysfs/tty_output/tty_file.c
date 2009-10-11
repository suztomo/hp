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

  read_lock(&tty_output_server.lock);
  list_for_each_entry(tty_o, &tty_output_server.list, list) {
    if (hp_node == tty_o->hp_node &&
        strcmp(tty_o->tty_name, file_fname) == 0) {
      bufsize += tty_o->size;
      opb = hp_alloc(sizeof(struct output_buf));
      list_add_tail(&opb->list, &output_buf_list);
    }
  }

  /*
    The buffer is freed by hp_release_control()
   */
  buf = hp_alloc(bufsize);
  list_for_each_entry(opb, &output_buf_list, list) {
    s = opb->tty_output->size;
    memcpy(buf, opb->tty_output->buf, s);
    wrote_count += s;
  }
  read_unlock(&tty_output_server.lock);

  /*
    Frees the list elements
   */
  while(!list_empty(&output_buf_list)) {
    opb = list_entry(output_buf_list.next, struct output_buf, list);
    list_del(&opb->list);
    kfree(opb);
  }


  /*
    the buffer will be freed in release_control
    the buffer is configured properly as partty.org
    file definitions.
   */
  io_buf->read_buf = buf;
  io_buf->readbuf_size = wrote_count;
  return;
}

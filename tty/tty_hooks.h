/*
  Functions definitions that replace system calls with path.
 */
int add_tty_hooks(void);
int remove_tty_hooks(void);




struct tty_output {
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


struct tty_output_saver {
  /* The contents of tty_output */
  struct tty_output *contents;
  /* The size of the tty_output */
  size_t size;
  /* the tail element */
  struct tty_output *cur;
}

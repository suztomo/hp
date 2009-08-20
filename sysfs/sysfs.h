/*
  Funcitons that manage /sys/kernel/security/hp/
 */

#define HP_DIR_NAME "hp"

int hp_init_sysfs(void);

int hp_cleanup_sysfs(void);

#define HP_IOBUF_WRITE_LEN 120
#define HP_IOBUF_READ_LEN 120

/*
  structure for honeypot interfaces between kernel and user space.
 */
struct hp_io_buffer {
  int (*read)(struct hp_io_buffer*);
  int (*write)(struct hp_io_buffer*);
  /* Exclusive lock for this structure */
  struct mutex io_sem;

  /* Buffer for read (not used) */
  char *read_buf;
  /* cursor for reading */
  int read_cur;
  /* sizeof the buffer */
  int readbuf_size;

  /* Buffer for write */
  char write_buf[HP_IOBUF_WRITE_LEN];
  /* cursor for writing */
  int write_cur;
  /* size of the buffer */
  int writebuf_size;
};

extern struct dentry * hp_dir_entry;


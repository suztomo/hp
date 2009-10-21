/*
  Funcitons that manage /sys/kernel/security/hp/
 */

#include "../common.h"

#ifndef HP_SYSFS

#define HP_DIR_NAME "hp"
#define HP_DENTRY_NUM 12
#define HP_DENTRY_KEY_ROOT             0 /* hp/ */
#define HP_DENTRY_KEY_NODECONF_IP      1 /* hp/nodeconf_ip */
#define HP_DENTRY_KEY_NODECONF_PORT    2 /* hp/nodeconf_port */
#define HP_DENTRY_KEY_TTY_OUTPUT       3 /* hp/tty_output */
#define HP_DENTRY_KEY_TTY_OUTPUT_SETUP 4 /* hp/tty_output_setup */
#define HP_DENTRY_KEY_TTY_OUTPUT_ALL   5 /* hp/tty_output/all */

/*
  The two below are not entries in hp_dentries[].
 */
#define HP_DENTRY_KEY_TTY_OUTPUT_NODE     6 /* hp/tty_output/<node num>/ */
#define HP_DENTRY_KEY_TTY_OUTPUT_NODE_TTY 7 /* hp/tty_output/<node num>/pts5 */



#define HP_TTY_OUTPUT_DIR_NAME "tty_output"
#define HP_TTY_OUTPUT_ALL_NAME "all"
#define HP_TTY_OUTPUT_DENTRY_NUM 1000

int hp_init_sysfs(void);
int hp_cleanup_sysfs(void);

int hp_init_tty_output_sysfs(void);
int hp_cleanup_tty_output_sysfs(void);

#define HP_IOBUF_WRITE_LEN 120
#define HP_IOBUF_READ_LEN 120

extern struct dentry *hp_dentries[HP_DENTRY_NUM];

/*
  Structure for honeypot interfaces between kernel and user space.
 */
struct hp_io_buffer {
  ssize_t (*read)(struct hp_io_buffer*, struct file *file, char __user *buf,
              size_t count, loff_t *ppos);
  int (*write)(struct hp_io_buffer*);
  void (*release)(struct hp_io_buffer*);

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

/*
  Record directory entries for removing them.
  Since the size of them is unknown, I use list for them.
 */
struct tty_dentry {
  struct list_head list;
  struct dentry *de;
};

struct tty_dentry_server {
  struct list_head list;
  rwlock_t lock;
};

extern struct tty_dentry_server tty_dentry_server;

extern struct dentry * hp_dir_entry;

extern wait_queue_head_t hp_tty_output_wait_queue;

/*
  General interfaces for special files.
 */
int hp_open(struct inode *inode, struct file *file);
int hp_release(struct inode *inode, struct file *file);
ssize_t hp_read(struct file *file, char __user *buf,
                size_t count, loff_t *ppos);
int hp_write(struct file *file, const char __user *buf,
             size_t count, loff_t *ppos);

/*
  Specific interfaces for special files.
  Called when the file is opened.
 */
int hp_nodeconf_ip_write(struct hp_io_buffer *buf);
void hp_nodeconf_ip_setup_readbuf(struct hp_io_buffer *io_buf);
int hp_nodeconf_port_write(struct hp_io_buffer *buf);
void hp_nodeconf_port_setup_readbuf(struct hp_io_buffer *io_buf);
void hp_tty_output_setup_readbuf(struct hp_io_buffer *io_buf,
                                 long int hp_node,
                                 const char *file_fname);
void hp_tty_output_all_setup_readbuf(struct hp_io_buffer *io_buf);
ssize_t hp_tty_output_all_read(struct hp_io_buffer *io_buf,
                               struct file *file, char __user *ubuf,
                               size_t count, loff_t *ppos);


int hp_tty_output_prepare_output_files(void);
struct dentry * hp_create_tty_entry(const char *name, const mode_t mode,
                                    struct dentry *parent, const u8 key);
int hp_create_dentry_tty_output_hp_node_tty(long int hp_node, char *tty_name);


int hp_tty_output_create_tty_output_all(struct dentry *parent);
void hp_tty_output_all_close(struct hp_io_buffer *io_buf);


inline const unsigned char *file_fname(struct file *file);
inline const unsigned char *file_parent_dname(struct file *file);
inline const unsigned char *dentry_fname(struct dentry *de);
inline const unsigned char *dentry_parent_dname(struct dentry *de);




#define HP_SYSFS
#endif

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/security.h>
#include <linux/seq_file.h>
#include <asm/uaccess.h>

#include "../sysfs.h"
#include "../../tty/tty_hooks.h"

/*
  Initializes /sys/kernel/security/hp/tty_output/.
  This function must be called after hp_init_sysfs().
 */

/*
  Initialized to NULL?
 */
struct dentry *hp_tty_output_dentries[HP_TTY_OUTPUT_DENTRY_NUM];


/*
  Creates a directory for tty_output as "/tty_output/<hp_node>/"
  specifying <hp_node>
 */
#include <linux/fsnotify.h>


void notify_dir_creation_to_parent(struct dentry *dentry)
{
    if (dentry->d_parent->d_inode) {
      fsnotify_mkdir(dentry->d_parent->d_inode, dentry);
    } else{
      debug("inode of the parent directory is NULL");
    }
    return;
}

int create_dentry_tty_output_hp_node(long int hp_node)
{
  struct dentry *parent_dir = hp_dentries[HP_DENTRY_KEY_TTY_OUTPUT];
  struct dentry *hp_node_dir;
  char dir_name[12];
  if (hp_tty_output_dentries[hp_node])
    return 0;

  if (!parent_dir) {
    alert("parent directory(tty_output) is not initialized.\n");
    return -ENODEV;
  }
  if (hp_node > HP_TTY_OUTPUT_DENTRY_NUM - 1) {
    alert("Too large hp_node number.\n");
    return -ENODEV;
  }
  /*
    Create directory name using (int)hp_node.
   */
  snprintf(dir_name, sizeof(dir_name), "%ld", hp_node);
  dir_name[sizeof(dir_name)-1] = '\0';

  /*
    Creates directory.
   */
  hp_node_dir = securityfs_create_dir(dir_name, parent_dir);
  if (!hp_node_dir) {
    alert("failed securityfs_create_dir.\n");
  } else if ((int)hp_node_dir == -ENODEV) {
    /*
      Parent is missing
     */
    alert("securityfs is not enabled in this machine.\n");
    hp_node_dir = NULL;
  } else {
    /*
      Success, notifies the creation to parent.
      see ~/inotify.sh
     */
    notify_dir_creation_to_parent(hp_node_dir);
    debug("Created tty_output/%ld", hp_node);
  }
  hp_tty_output_dentries[hp_node] = hp_node_dir;
  return 0;
}


//struct list_head node_tty_list[HP_TTY_OUTPUT_DENTRY_NUM];


/*
  The operations to show the tty outputs.
 */
static const struct file_operations hp_tty_output_operations = {
  .open = hp_open,
  .release = hp_release,
  .read = hp_read,
  .write = hp_write
};

struct tty_dentry_server tty_dentry_server;


struct dentry * hp_create_tty_entry(const char *name, const mode_t mode,
                                        struct dentry *parent, const u8 key)
{
  struct dentry *new_dentry;
  new_dentry = securityfs_create_file(name, mode, parent,
                                      ((u8 *)NULL) + key,
                                      &hp_tty_output_operations);
  if (new_dentry) {
    notify_dir_creation_to_parent(new_dentry);
    debug("Created %s in tty_output.\n", name);
  } else {
    alert("Failed creating %s in tty_output.\n", name);
  }
  return new_dentry;
}

/*
  Creates output file as "/sys/kernel/security/hp/tty_output/32/tty33"
  specifying <hp_node> and <tty_name>
 */
int create_dentry_tty_output_hp_node_tty(long int hp_node, char *tty_name)
{
  int ret;
  struct dentry *parent;
  int mode = 0444;
  struct dentry *de;
  struct tty_dentry *td;


  /*
    Firstly checks the existence of the parent directory <hp_node>
   */
  if (!hp_tty_output_dentries[hp_node]) {
    ret = create_dentry_tty_output_hp_node(hp_node);
    if (ret) {
      alert("Cannot create parent directory %ld/\n.", hp_node);
      return ret;
    }
  }
  parent = hp_tty_output_dentries[hp_node];
  if (!parent) {
    alert("Parent is not created");
    return -ENODEV;
  }
  de = hp_create_tty_entry(tty_name, mode, parent, 
                        HP_DENTRY_KEY_TTY_OUTPUT_NODE_TTY);
  /*
    Record in the tty_dentry_server.list
    of the tty's dentries for hp_cleanup_tty_output_sysfs().
   */
  td = hp_alloc(sizeof(struct tty_dentry));
  td->de = de;
  write_lock(&tty_dentry_server.lock);
  list_add_tail(&(td->list), &tty_dentry_server.list);
  write_unlock(&tty_dentry_server.lock);
  return 0;
}

struct tty_output_filename {
  struct list_head list;
  long int hp_node;
  char tty_name[TTY_NAME_LEN];
};

#define STRCMP_SAME 0

/*
  Creates files named "/hp/tty_output/<hp_node>/<tty_name>".
  Currently I use "list" for checking the existence of the file
  because it does not require speed and list is easy to use.
  But another container, like set in C++, is more preferable.
 */
int hp_tty_output_prepare_output_files(void)
{
  struct list_head tty_output_filename_list;
  struct tty_output_filename *tof;
  struct hp_message *msg;
  int already;
  int r = 0;
  INIT_LIST_HEAD(&tty_output_filename_list);

  read_lock(&message_server.lock);
  list_for_each_entry(msg, &message_server.list, list) {
    already = 0;
    list_for_each_entry(tof, &tty_output_filename_list, list) {
      if (tof->hp_node == msg->c.tty_output.hp_node &&
          strcmp(tof->tty_name, msg->c.tty_output.tty_name) == STRCMP_SAME) {
        already = 1;
        break;
      }
    }
    if (!already) {
      tof = hp_alloc(sizeof(struct tty_output_filename));
      tof->hp_node = msg->c.tty_output.hp_node;
      strncpy(tof->tty_name, msg->c.tty_output.tty_name, sizeof(tof->tty_name));
      list_add_tail(&(tof->list), &tty_output_filename_list);
    }
  }
  read_unlock(&message_server.lock);

  /*
    Creates the directories and files and frees the list elements
   */
  while(!list_empty(&tty_output_filename_list)) {
    tof = list_entry(tty_output_filename_list.next, struct tty_output_filename,
                     list);
    /* If a error occurs, the return value become the error */
    r = create_dentry_tty_output_hp_node_tty(tof->hp_node, tof->tty_name);
    list_del(&(tof->list));
    kfree(tof);
  }

  return r;
}

#include <linux/spinlock.h>

/*
  Initializes the directory "/sys/kernel/security/hp/tty_output/"
  The directory itself (hp/tty_output) is created in sysfs/root.c
 */
int hp_init_tty_output_sysfs(void)
{
  struct dentry *hp_dir_entry = hp_dentries[HP_DENTRY_KEY_ROOT];
  struct dentry *hp_tty_output_entry = hp_dentries[HP_DENTRY_KEY_TTY_OUTPUT];
  INIT_LIST_HEAD(&tty_dentry_server.list);
  rwlock_init(&tty_dentry_server.lock);
  if (!hp_dir_entry) {
    alert("parent directory is not initialized.");
    return -ENODEV;
  }
  if (!hp_tty_output_entry) {
    alert("tty_output directory is not initialized.");
    return -ENODEV;
  }

  /*
    Creates /hp/tty_output/all
   */
  hp_tty_output_create_tty_output_all(hp_tty_output_entry);
  return 0;
}


/*
  Finalizes /sys/kernel/security/hp/tty_output/
 */
int hp_cleanup_tty_output_sysfs(void)
{
  int i = 0;
  struct tty_dentry *td;
  /*
    Removes tty file "hp/tty_output/<hp_node>/tty32" firstly
   */
  while(!list_empty(&tty_dentry_server.list)) {
    td = list_entry(tty_dentry_server.list.next, struct tty_dentry, list);
    debug("*** deleting %d\n", i++);
    list_del(&(td->list));
    securityfs_remove(td->de);
  }

  /*
    Removes directories "hp/tty_output/<hp_node>.
    The tty_output directory itself is unloaded by hp_cleanup_sysfs().
   */
  for (i=0; i<HP_TTY_OUTPUT_DENTRY_NUM; ++i) {
    struct dentry *de = hp_tty_output_dentries[HP_TTY_OUTPUT_DENTRY_NUM - i - 1];
    if (de) {
      debug("removing. %s in tty_output", dentry_fname(de));
      securityfs_remove(de);
    }
  }
  return 0;
}

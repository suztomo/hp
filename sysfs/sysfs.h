/*
  Funcitons that manage /sys/kernel/security/hp/
 */

#define HP_DIR_NAME "hp"

int hp_init_sysfs(void);

int hp_cleanup_sysfs(void);

extern struct dentry * hp_dir_entry;


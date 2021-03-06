/*
  Common routines and definitions.
 */

#ifndef HP_COMMON
#define HP_COMMON

void *hp_alloc(size_t size);
void hp_free(void *p);

#define HP_NODE_NUM 1000
#define HP_GLOBAL_NODE_OFFSET HP_NODE_NUM
#define HP_GL_NODE_NUM 1000

#define debug(...) { \
  printk(KERN_DEBUG __VA_ARGS__);\
  printk(KERN_DEBUG "   - %s:%u @%s ", __FILE__, __LINE__, __func__);}
#define alert(...) {printk(KERN_ALERT __VA_ARGS__);}

extern unsigned char hp_node_ipaddr[HP_NODE_NUM+1][4];
extern int hp_node_port[HP_NODE_NUM+1];


#define IS_OBSERVED() ((current)->hp_node >= 0)
#define NOT_OBSERVED() (!IS_OBSERVED())

#endif

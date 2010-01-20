#include <linux/kernel.h>
#include <linux/module.h>

#include "common.h"

/*
  Allocates specified-sized region.
 */
void *hp_alloc(size_t size)
{
  void *p = kzalloc(size, GFP_KERNEL);
  if (!p) {
    alert("no mem");
  }
  return p;
}

/*
  Frees the region.
*/
void hp_free(void *p)
{
  kfree(p);
}

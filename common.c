#include <linux/kernel.h>
#include <linux/module.h>

#include "common.h"

void *hp_alloc(const size_t size)
{
  void *p = kzalloc(size, GFP_KERNEL);
  if (!p) {
    alert("no mem");
  }
  return p;
}

void hp_free(const void *p)
{
  kfree(p);
}

#include <sys/utsname.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>

#define CNUM 10000
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

suseconds_t tvdiff_usec(struct timeval *before,
                        struct timeval *after)
{
  suseconds_t before_usec = before->tv_usec + before->tv_sec * 1000000;
  suseconds_t after_usec = after->tv_usec + after->tv_sec * 1000000;
  return after_usec - before_usec;
}

int main(int argc, char *argv[])
{
  int i;
  struct utsname un;
  int r;
  int sumdiff;
  struct timeval tv0, tv1;
  for (i=0; i<CNUM; ++i) {
    gettimeofday(&tv0, NULL);
    r = uname(&un);
    gettimeofday(&tv1, NULL);
    if (r != 0) {
      perror("uname");
      break;
    }
    sumdiff += tvdiff_usec(&tv0, &tv1);
  }
  printf("  Sum diff: %d (usec) in %d loops\n", sumdiff, CNUM);
  printf("  Usec per uname: %0.3f (usec)\n", (double)sumdiff/CNUM);
  return 0;
}

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int main(int argc, char *argv[])
{
  int ret;
  printf("%d\n", geteuid());
  ret = execvp("apache2ctl", argv);
  if (ret) {
    perror("execvp");
  }
  return 0;
}

#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>

#define CNUM 1000
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <errno.h>

suseconds_t tvdiff_usec(struct timeval *before,
                        struct timeval *after)
{
  suseconds_t before_usec = before->tv_usec + before->tv_sec * 1000000;
  suseconds_t after_usec = after->tv_usec + after->tv_sec * 1000000;
  return after_usec - before_usec;
}

int main(int argc, char *argv[])
{
  struct timeval tv0, tv1;
  int i;
  int sockfd;
  struct sockaddr_in serv;
  char *serv_addr;
  unsigned short port;
  int d;
  int sumdiff;
  int sockfds[CNUM];
  if (argc != 3) {
    printf("Specify address and port");
    return 1;
  }

  port = atoi(argv[2]);
  if (port >= 2<<16) {
    printf("invalid port %d", port);
    return 1;
  }
  serv_addr = argv[1];

  inet_aton(serv_addr, &(serv.sin_addr));
  serv.sin_port = htons(port);
  serv.sin_family = PF_INET;

  for (i=0; i<CNUM; ++i) {
    sockfd =  socket(PF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
      perror("socket");
      return 1;
    }
    sockfds[i] = sockfd;
  }
  gettimeofday(&tv0, NULL);
  for (i=0; i<CNUM; ++i) {
    sockfd = sockfds[i];
    d = connect(sockfd, (struct sockaddr*)&serv, sizeof(serv));
    continue;
    /*
    if (d != 0) {
      if (d != 111) { // connection refused
        printf("errno %d\n", errno);
        perror("connect");
        break;
      }
      }*/
  }
  gettimeofday(&tv1, NULL);
  sumdiff = tvdiff_usec(&tv0, &tv1);
  for (i=0; i<CNUM; ++i) {
    sockfd = sockfds[i];
    close(sockfd);
  }
  printf("  Sum diff: %d (usec) in %d loops\n", sumdiff, CNUM);
  printf("  Usec per connect: %0.3f (usec)\n", (double)sumdiff/CNUM);
  return 0;
}


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <cuishark.h>
#include <hexdump.h>


void* front(void* __arg__)
{
  while (cuishark_loop_running()) {
    if (!cuishark_msg_queue_empty()) {

      packet_t* m = cuishark_msgqueue_pop();
      node_t* n = cuishark_msg_node(m);

      printf("%s\n", node_line(n));
      for (size_t i=0; i<node_childs_num(n); i++) {
        node_t* cn = node_child(n, i);
        print_csnode(cn, 0);
      }
      hexdump(stdout, cuishark_msg_data_ptr(m), cuishark_msg_data_len(m));
      printf("\n\n");

    }
  }
  printf("finish\n");
  return NULL;
}

void* back(void* arg)
{
  char** argv = (char**)arg;
  int argc;
  for (argc=0; argv[argc]; argc++) ;
  cuishark_init(argc, argv);
  cuishark_capture();
  cuishark_fini();
  return NULL;
}

void exec_cmd(int argc, char** argv)
{
  if (strcmp(argv[0], "df") == 0) cuishark_apply_dfilter(argv[1]);
  else if (strcmp(argv[0], "clear") == 0) cuishark_apply_dfilter("");
  else if (strcmp(argv[0], "dump") == 0) cuishark_status_dump();
  else if (strcmp(argv[0], "print") == 0) cuishark_packets_dump();
  else if (strcmp(argv[0], "quit") == 0) exit(0);
}

void* cmdfunc(void* arg)
{
  while (cuishark_loop_running()) {
    printf(">>> ");
    char str[100];
    fgets(str, sizeof(str), stdin);
    str[strlen(str)-1] = 0;

    int argc = 0;
    char* argv[100];
    argv[argc] = str;
    size_t len = strlen(str) + 1;
    for (size_t i=1; i<len; i++) {
      if (str[i] == ' ' || str[i] == 0) {
        str[i] = 0;
        argc ++;
        argv[argc] = &str[i+1];
      }
    }
    exec_cmd(argc, argv);
  }
}

int main(int argc, char** argv)
{
  pthread_t frontend;
  pthread_t backend;
  pthread_t cmd;

  pthread_create(&frontend, NULL, front, NULL);
  pthread_create(&backend , NULL, back, argv);
  pthread_create(&cmd, NULL, cmdfunc, NULL);

  pthread_join(frontend, NULL);
  pthread_join(backend, NULL);
  pthread_join(cmd, NULL);
}


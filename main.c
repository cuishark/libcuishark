
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
  return NULL;
}

int main(int argc, char** argv)
{
  pthread_t frontend;
  pthread_t backend;
  pthread_create(&frontend, NULL, front, NULL);
  pthread_create(&backend , NULL, back, argv);
  pthread_join(frontend, NULL);
  pthread_join(backend, NULL);
}

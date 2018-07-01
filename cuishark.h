
#ifndef _CUISHARK_H_
#define _CUISHARK_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef struct csnode node_t;
typedef struct packet packet_t;

bool cuishark_loop_running();
int cuishark_init(int argc, char *argv[]);
int cuishark_capture();
void cuishark_fini();
bool cuishark_msg_queue_empty();

packet_t* cuishark_msgqueue_pop();
const uint8_t* cuishark_msg_data_ptr(packet_t* m);
size_t cuishark_msg_data_len(packet_t* m);
node_t* cuishark_msg_node(packet_t* m);

void print_csnode(node_t* node, int level);
const char* node_line(node_t* node);
size_t node_childs_num(node_t* node);
node_t* node_child(node_t* node, size_t idx);
size_t node_level(node_t* n);
bool node_isopen(node_t* n);
void node_isopen_switch(node_t* n);
node_t* get_node_from_root(node_t* root, int idx);
const char* get_interface_name();

void cuishark_apply_dfilter(const char* filter_string);
size_t cuishark_num_displayed_packets();
size_t cuishark_num_captured_packets();
void cuishark_packets_dump();
void cuishark_status_dump();


#ifdef __cplusplus
} // extern C
#endif

#endif /* _CUISHARK_H_ */


#ifndef __NIC_MESSAGE_H__
#define __NIC_MESSAGE_H__

#include <nic_server.h>

typedef enum {
	NC_INT,
	NC_FLOAT,
	NC_CHAR,
	NC_STRING,
	NC_NONE,
}nc_item_type;

typedef struct nc_packet *nc_msg_handle;

nic_result_s nic_init_msg(nc_msg_handle *hnd);
nic_result_s nic_deinit_msg(nc_msg_handle hnd);

nic_result_s nic_set_int(nc_msg_handle hnd, int data);
nic_result_s nic_set_float(nc_msg_handle hnd, float data);
nic_result_s nic_set_char(nc_msg_handle hnd, char data);
nic_result_s nic_set_string(nc_msg_handle hnd, char *data);

nic_result_s nic_set_msg(nc_msg_handle hnd, char *buf);
nic_result_s nic_gen_msg(nc_msg_handle hnd, uint8_t **buf, uint16_t buf_len);

nic_result_s nic_get_item(nc_msg_handle hnd, nc_item_type *type, void *data, uint32_t *data_len);
nic_result_s nic_next_item(nc_msg_handle hnd);

#endif __NIC_MESSAGE_H__

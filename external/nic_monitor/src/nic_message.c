#ifndef LINUX
#include <tinyara/config.h>
#endif
#include <stdint.h>
#include <nic_message.h>


struct _nc_item {
	nc_item_type type;
	uint8_t data_len;
	void *data;
};

struct nc_packet {

};

/**
 * APIs
 */
nic_result_s nic_init_msg(nc_msg_handle *hnd)
{

}

nic_result_s nic_deinit_msg(nc_msg_handle hnd)
{

}

nic_result_s nic_set_int(nc_msg_handle hnd, int data)
{

}

nic_result_s nic_set_float(nc_msg_handle hnd, float data)
{

}

nic_result_s nic_set_char(nc_msg_handle hnd, char data)
{

}

nic_result_s nic_set_string(nc_msg_handle hnd, char *data)
{

}

nic_result_s nic_set_msg(nc_msg_handle hnd, char *buf)
{

}

nic_result_s nic_gen_msg(nc_msg_handle hnd, uint8_t **buf, uint16_t buf_len)
{

}

nic_result_s nic_get_item(nc_msg_handle hnd, nc_item_type *type, void *data)
{

}

nic_result_s nic_next_item(nc_msg_handle hnd)
{

}

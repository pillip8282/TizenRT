#ifndef __NIC_MESSAGE_H__
#define __NIC_MESSAGE_H__

#include <nic_monitor.h>
#include <stdint.h>
#include <string.h>

/* NIC flags */
#define NIC_MEMCPY       0x0001        /* Newly allocate memory */
#define NIC_GETREF       0x0002        /* Return pointer without memeory allocation */

typedef enum {
	NIC_INT,
	NIC_FLOAT,
	NIC_CHAR,
	NIC_STRING,
	NIC_BUF,
	NIC_NONE,
}nic_item_type;

typedef struct nic_context *nic_msg_handle;

nic_result_s nic_init_msg(nic_msg_handle *hnd, nic_type type);
nic_result_s nic_deinit_msg(nic_msg_handle hnd);

nic_result_s nic_set_int(nic_msg_handle hnd, int data);
nic_result_s nic_set_float(nic_msg_handle hnd, float data);
nic_result_s nic_set_char(nic_msg_handle hnd, char data);
nic_result_s nic_set_string(nic_msg_handle hnd, char *data);
nic_result_s nic_set_buf(nic_msg_handle hnd, void *data, int data_len);

nic_result_s nic_set_msg(nic_msg_handle hnd, char *buf);
nic_result_s nic_gen_msg(nic_msg_handle hnd, uint8_t **buf, int *buf_len);

nic_result_s nic_get_msg(char *buf, int buf_len, nic_msg_handle hnd);
nic_result_s nic_get_next(nic_msg_handle hnd, nic_item_type *type, uint8_t **data, int flag);
#endif //__NIC_MESSAGE_H__

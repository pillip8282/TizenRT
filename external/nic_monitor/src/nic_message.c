#ifndef LINUX
#include <tinyara/config.h>
#endif
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <nic_message.h>
#include <nic_monitor.h>
#include <nic_util.h>

struct _nic_item {
	nic_item_type type;
	int data_len;
	void *data;
};

struct nic_packet {
	struct _nic_item item;
	struct nic_packet *next;
};

struct nic_context {
	int next_idx;
	struct nic_packet *head; //packet list
	int cnt;
	nic_type type;
};

/**
 * Definitions
 */
#define ENCODE_PACKET(dest, src, type_size, pos)                 \
	do {                                                         \
		memcpy(dest + pos, &(src.type), sizeof(nic_item_type));  \
		pos += sizeof(nic_item_type);                            \
		memcpy(dest + pos, &(src.data_len), sizeof(int));        \
		pos += sizeof(int);                                      \
		memcpy(dest + pos, src.data, type_size);                 \
		pos += type_size;                                        \
	} while (0)

#define DECODE_PACKET(dest, src, pos)                            \
	do {                                                         \
		memcpy(&(dest.type), src + pos, sizeof(nic_item_type));  \
		pos += sizeof(nic_item_type);                            \
		memcpy(&(dest.data_len), src + pos, sizeof(int));        \
		pos += sizeof(int);                                      \
		char *tmp_data = (char *)malloc(dest.data_len);          \
		memcpy(tmp_data, src + pos, dest.data_len);              \
		dest.data = tmp_data;                                    \
		pos += dest.data_len;                                    \
	} while (0)

/**
 * Internal APIs
 */
void _nic_addpacket(struct nic_packet *packet, nic_msg_handle hnd)
{
	struct nic_packet *prev;
	if (hnd->head) {
		for (prev = (struct nic_packet *)hnd->head; prev->next; prev = prev->next);
		prev->next = packet;
	} else {
		hnd->head = packet;
	}
	hnd->cnt++;

	return;
}

int _nic_calc_buflen(nic_msg_handle hnd)
{
	struct nic_packet *prev;
	int buf_len = 0;

	if (hnd->head) {
		
		//NIC_TYPE
		buf_len += sizeof(nic_type);
		for (prev = (struct nic_packet *)hnd->head; prev; prev = prev->next) {
			//data length
			buf_len += sizeof(int);
			//data type
			buf_len += sizeof(nic_item_type);
			//actual data
			buf_len += prev->item.data_len;
		}
		return buf_len;
	}

	return 0;
}

/**
 * APIs
 */
nic_result_s nic_init_msg(nic_msg_handle *hnd, nic_type type)
{
	struct nic_context *pkt_list = (struct nic_context *)malloc(sizeof(struct nic_context));
	if(!pkt_list) {
		NIC_ERR;
		return NIC_MEM_FAIL;
	}
	pkt_list->head = NULL;
	pkt_list->cnt = 0;
	pkt_list->next_idx = 0;
	pkt_list->type = type;
	*hnd = pkt_list;

	return NIC_SUCCESS;
}

nic_result_s nic_deinit_msg(nic_msg_handle hnd)
{
	struct nic_packet *cur;
	if (hnd->head) {
		int k = 0;
		for (cur = (struct nic_packet*)hnd->head; cur; cur = hnd->head) {
			hnd->head = cur->next;
			free(cur->item.data);
			free(cur);
		}
	}
	free(hnd);

	return NIC_SUCCESS;
}

/**
 * server-speicifc APIs
 */
nic_result_s nic_set_int(nic_msg_handle hnd, int data)
{
	struct nic_packet *pkt = (struct nic_packet *)malloc(sizeof(struct nic_packet));
	if(!pkt) {
		NIC_ERR;
		return NIC_MEM_FAIL;
	}

	int *data_cpy = (int *)malloc(sizeof(int));
	if(!data_cpy) {
		NIC_ERR;
		free(pkt);
		return NIC_MEM_FAIL;
	}
	memcpy(data_cpy, &data, sizeof(int));

	pkt->item.type = NIC_INT;
	pkt->item.data_len = sizeof(int);
	pkt->item.data = data_cpy;
	pkt->next = NULL;
	_nic_addpacket(pkt, hnd);
	return NIC_SUCCESS;
}

nic_result_s nic_set_float(nic_msg_handle hnd, float data)
{
	struct nic_packet *pkt = (struct nic_packet *)malloc(sizeof(struct nic_packet));
	if(!pkt) {
		NIC_ERR;
		return NIC_MEM_FAIL;
	}

	float *data_cpy = (float *)malloc(sizeof(float));
	if(!data_cpy) {
		NIC_ERR;
		free(pkt);
		return NIC_MEM_FAIL;
	}
	memcpy(data_cpy, &data, sizeof(float));

	pkt->item.type = NIC_FLOAT;
	pkt->item.data_len = sizeof(float);
	pkt->item.data = data_cpy;
	pkt->next = NULL;
	_nic_addpacket(pkt, hnd);

	return NIC_SUCCESS;
}

nic_result_s nic_set_char(nic_msg_handle hnd, char data)
{
	struct nic_packet *pkt = (struct nic_packet *)malloc(sizeof(struct nic_packet));
	if(!pkt) {
		NIC_ERR;
		free(pkt);
		return NIC_MEM_FAIL;
	}

	char *data_cpy = (char *)malloc(sizeof(char));
	if(!data_cpy) {
		NIC_ERR;
		free(pkt);
		return NIC_MEM_FAIL;
	}
	memcpy(data_cpy, &data, sizeof(char));

	pkt->item.type = NIC_CHAR;
	pkt->item.data_len = sizeof(char);
	pkt->item.data = data_cpy;
	pkt->next = NULL;
	_nic_addpacket(pkt, hnd);

	return NIC_SUCCESS;
}

nic_result_s nic_set_string(nic_msg_handle hnd, char *data)
{
	struct nic_packet *pkt = (struct nic_packet *)malloc(sizeof(struct nic_packet));
	if(!pkt) {
		NIC_ERR;
		return NIC_MEM_FAIL;
	}
	char *data_cpy = (char *)malloc(strlen(data) + 1);
	if(!data_cpy) {
		NIC_ERR;
		free(pkt);
		return NIC_MEM_FAIL;
	}
	strncpy(data_cpy, data, strlen(data) + 1);

	pkt->item.type = NIC_STRING;
	pkt->item.data_len = strlen(data) + 1;
	pkt->item.data = data_cpy;
	pkt->next = NULL;
	_nic_addpacket(pkt, hnd);

	return NIC_SUCCESS;
}

nic_result_s nic_set_buf(nic_msg_handle hnd, void *data, int data_len)
{
	struct nic_packet *pkt = (struct nic_packet *)malloc(sizeof(struct nic_packet));
	if(!pkt) {
		NIC_ERR;
		return NIC_MEM_FAIL;
	}
	void *data_cpy = (void *)malloc(data_len);
	if(!data_cpy) {
		NIC_ERR;
		free(pkt);
		return NIC_MEM_FAIL;
	}
	memcpy(data_cpy, data, data_len);

	pkt->item.type = NIC_BUF;
	pkt->item.data_len = data_len;
	pkt->item.data = data_cpy;
	pkt->next = NULL;
	_nic_addpacket(pkt, hnd);

	return NIC_SUCCESS;
}
nic_result_s nic_gen_msg(nic_msg_handle hnd, uint8_t **buf, int *buf_len)
{
	struct nic_packet *prev;
	int pos = 0;
	*buf_len = _nic_calc_buflen(hnd);
	char *new_buf = (char *)malloc(*buf_len);
	if(!new_buf) {
		NIC_ERR;
		return NIC_MEM_FAIL;
	}
	if (hnd->head) {
		memcpy(new_buf, &(hnd->type), sizeof(nic_type));
		pos += sizeof(nic_type);
		for (prev = (struct nic_packet *)hnd->head; prev; prev = prev->next) {
			ENCODE_PACKET(new_buf, prev->item, prev->item.data_len, pos);
		}
	} else {
		NIC_ERR;
		free(new_buf);
		return NIC_FAIL;
	}
	*buf = new_buf;

	return NIC_SUCCESS;
}

/**
 * client-specific APIs
 */
nic_result_s nic_get_msg(char *buf, int buf_len, nic_msg_handle hnd)
{
	int pos = 0;
	if(hnd) {
		memcpy(&hnd->type, buf, sizeof(nic_type));
		pos += sizeof(nic_type);
	} else {
		NIC_ERR;
		return NIC_FAIL;
	}
	while (pos + 1 < buf_len) {
		struct nic_packet *pkt = (struct nic_packet *)malloc(sizeof(struct nic_packet));
		if(!pkt) {
			NIC_ERR;
			return NIC_MEM_FAIL;
		}
		DECODE_PACKET(pkt->item, buf, pos);
		pkt->next = NULL;
		_nic_addpacket(pkt, hnd);
	}
	return NIC_SUCCESS;
}

nic_result_s nic_get_next(nic_msg_handle hnd, nic_item_type *type, uint8_t **data, int flag)
{
	struct nic_packet *cur;
	if (hnd->head && hnd->next_idx < hnd->cnt) {
		cur = (struct nic_packet *)hnd->head;
		for (int i = 0; i < hnd->next_idx; i++) {
			cur = cur->next;
		}
		switch(flag) {
			case NIC_MEMCPY: 
			{
				char *buf = (char *)malloc(cur->item.data_len);
				if (!buf) {
					NIC_ERR;
					return NIC_MEM_FAIL;
				}
				memcpy(buf, cur->item.data, cur->item.data_len);
				*data = buf;
				*type = cur->item.type;
				break;
			}
			case NIC_GETREF:
				*data = cur->item.data;
				*type = cur->item.type;
				break;
			default:
				NIC_ERR;
				return NIC_FAIL;
		}
		hnd->next_idx++;
	} else {
		return NIC_FAIL;
	}
	return NIC_SUCCESS;
}


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <nic_monitor.h>
#include <nic_message.h>
#include <nic_util.h>

#define NIC_RESULT(func)						\
	do {										\
		res = func;								\
		if (res != NIC_SUCCESS) {				\
			NIC_ERR;							\
		} else {								\
			NIC_PASS;							\
		}										\
	} while (0)

static nic_result_s print_client_msg(nic_item_type type, void *data)
{
	switch (type) {
		case NIC_INT:
			printf("rxdata %d\n", *(int *)data);
			break;
		case NIC_FLOAT:
			printf("rxdata %f\n", *(float *)data);
			break;
		case NIC_CHAR:
			printf("rxdata %c\n", *(char *)data);
			break;
		case NIC_STRING:
			printf("rxdata %s\n", (char *)data);
			break;
		case NIC_BUF:
			printf("rxdata %s\n", (char *)data);
			break;
		default:
			NIC_ERR;
			return NIC_FAIL;
	}
}

static void *client1_handler(nic_msg_s *msg, void *arg)
{
	NIC_ENTRY;
	nic_msg_handle msg_hnd;
	nic_init_msg(&msg_hnd, NIC_TYPE_WIFI);
	nic_get_msg(msg->data, msg->len, msg_hnd);
	NIC_LOG("client #1: receive msg (%p, %p)\n", msg, arg);
	nic_item_type type;
	uint8_t *data = NULL;
	while(nic_get_next(msg_hnd, &type, (uint8_t **)&data, NIC_MEMCPY) == NIC_SUCCESS) {
		print_client_msg(type, (void *)data);
		free(data);
	}
	nic_deinit_msg(msg_hnd);
	NIC_OUT;
}

static void *client2_handler(nic_msg_s *msg, void *arg)
{
	NIC_ENTRY;
	nic_msg_handle msg_hnd;
	nic_init_msg(&msg_hnd, NIC_TYPE_BT);
	nic_get_msg(msg->data, msg->len, msg_hnd);
	NIC_LOG("client #2: receive msg (%p, %p)\n", msg, arg);
	nic_item_type type;
	uint8_t *data;
	while(nic_get_next(msg_hnd, &type, (uint8_t **)&data, NIC_GETREF) == NIC_SUCCESS) {
		print_client_msg(type, data);
	}
	nic_deinit_msg(msg_hnd);
	NIC_OUT;
}

static void basic_test1(void)
{
	NIC_ENTRY;
	char *data_s1 = "First String!";
	char *data_s2 = "Second String!";
	char *data_s3 = "Third String!";
	char *buf_tmp = "THIS IS VOID";

	nic_result_s res = NIC_FAIL;
    // run server
	NIC_RESULT(nic_server_start());
    // run client
	nc_handle c1;
	nc_handle c2;
	NIC_RESULT(nic_client_register(client1_handler, 0, &c1, NIC_TYPE_WIFI));
	NIC_RESULT(nic_client_register(client2_handler, 0, &c2, NIC_TYPE_BT));

    // create a event in server and check that both clients receive event.
	nic_msg_s msg;
	nic_msg_handle msg_hnd;

	nic_init_msg(&msg_hnd, NIC_TYPE_WIFI);
	nic_set_float(msg_hnd, 10.1);
	nic_set_string(msg_hnd, data_s1);
	nic_set_int(msg_hnd, 101010);
	nic_set_char(msg_hnd, 'a');
	nic_set_buf(msg_hnd, (void *)buf_tmp, strlen(buf_tmp) + 1);
	nic_gen_msg(msg_hnd, (uint8_t **)&(msg.data), &(msg.len));
	nic_deinit_msg(msg_hnd);

	nic_broadcast_event(&msg);
	free(msg.data);

	// wait until both clients receive a message.
	NIC_LOG("wait event\n");
	sleep(1);

	//generate a event and check that client1 receive event.
	nic_init_msg(&msg_hnd, NIC_TYPE_BT);
	nic_set_float(msg_hnd, 20.2);
	nic_set_string(msg_hnd, data_s2);
	nic_set_int(msg_hnd, 202020);
	nic_set_char(msg_hnd, 'b');
	nic_set_buf(msg_hnd, (void *)buf_tmp, strlen(buf_tmp) + 1);
	nic_gen_msg(msg_hnd, (uint8_t **)&(msg.data), &(msg.len));
	nic_deinit_msg(msg_hnd);

	nic_broadcast_event(&msg);
	free(msg.data);

	NIC_LOG("wait second event\n");
	sleep(1); // wait

    // terminate client 1
	NIC_RESULT(nic_client_unregister(c1));

	// generate a event and check that nothing happens
	nic_init_msg(&msg_hnd, NIC_TYPE_WIFI);
	nic_set_float(msg_hnd, 30.3);
	nic_set_string(msg_hnd, data_s3);
	nic_set_int(msg_hnd, 303030);
	nic_set_char(msg_hnd, 'c');
	nic_set_buf(msg_hnd, (void *)buf_tmp, strlen(buf_tmp) + 1);
	nic_gen_msg(msg_hnd, (uint8_t **)&(msg.data), &(msg.len));
	nic_deinit_msg(msg_hnd);

	nic_broadcast_event(&msg);
	free(msg.data);

	// terminate client 2
	NIC_RESULT(nic_client_unregister(c2));
	NIC_RESULT(nic_server_stop());

	NIC_OUT;

	return ;
}


int
main(void)
{
	basic_test1();

	return 0;
}

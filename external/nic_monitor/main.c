#include <stdio.h>
#include <string.h>
#include <nic_server.h>
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

static void *client1_handler(nic_msg_s *msg, void *arg)
{
	NIC_ENTRY;
	NIC_LOG("client 1: receive msg (%p, %p)\n", msg, arg);
	NIC_OUT;
}

static void *client2_handler(nic_msg_s *msg, void *arg)
{
	NIC_ENTRY;
	NIC_LOG("client 2: receive msg (%p, %p)\n", msg, arg);
	NIC_OUT;
}


static void basic_test1(void)
{
	NIC_ENTRY;
	nc_handle c1, c2;
	nic_result_s res = NIC_FAIL;
    // run server
	NIC_RESULT(nic_server_start());
    // run client 1
	NIC_RESULT(nic_client_register(client1_handler, 0, &c1));
	// run client 2
	NIC_RESULT(nic_client_register(client2_handler, 0, &c2));

    // create a event in server and check that both clients receive event.
	nic_msg_s msg;
	char *data = "hello world";
	msg.data = data;
	msg.len = strlen(data) + 1;


	nic_broadcast_event(&msg);

	// wait until both clients receive a message.
	NIC_LOG("wait event\n");
	sleep(1);

    // terminate client 1
	NIC_RESULT(nic_client_unregister(c1));

	// generate a event and check that client1 receive event.
	char *data2 = "hello world2";
	msg.data = data2;
	msg.len = strlen(data2) + 1;
	nic_broadcast_event(&msg);

	NIC_LOG("wait second event\n");
	sleep(1); // wait

	// terminate client 1
	NIC_RESULT(nic_client_unregister(c2));

	// generate a event and check that nothing happens
	char *data3 = "hello world3";
	msg.data = data3;
	msg.len = strlen(data3) + 1;
	nic_broadcast_event(&msg);

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

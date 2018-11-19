#ifndef _NIC_SERVER_H__
#define _NIC_SERVER_H__

////////////////////////////////////////////////
//
// Common
//
////////////////////////////////////////////////
typedef enum nic_result_ {
	NIC_SUCCESS,
	NIC_FAIL,
} nic_result_s;

// todo: decide event type(add?)
typedef struct _nic_msg{
	int len;
	void *data;
} nic_msg_s;


////////////////////////////////////////////////
//
// Server side
//
////////////////////////////////////////////////

typedef void *(*serv_handler)(nic_msg_s *msg); // unnecessary callback!!!

nic_result_s nic_server_start(void);
nic_result_s nic_server_stop(void);

/* hidden API to test NIC */
nic_result_s nic_broadcast_event(nic_msg_s *msg);


////////////////////////////////////////////////
//
// Client side
//
////////////////////////////////////////////////

#define NIC_CLIENT_PORT 9098

typedef void *(*nic_event_handler)(nic_msg_s *msg, void *arg);

typedef struct nc_context *nc_handle;
nic_result_s nic_client_register(nic_event_handler handler, void *data, nc_handle *hnd);
nic_result_s nic_client_unregister(nc_handle hnd);
#endif

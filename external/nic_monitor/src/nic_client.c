/****************************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#ifndef LINUX
#include <tinyara/config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <sys/select.h>
#include <netinet/in.h>

#include <tiny_evtmgr.h>
#include <nic_server.h>
#include <nic_client_list.h>
#include <nic_util.h>

typedef enum {
	NC_INIT,
	NC_RECEIVE_MSG,
	NC_DEINIT,
} nc_msg_type_e;

struct nc_context {
	nic_event_handler handler;
	void *data;
};

typedef struct _nc_msg_s {
	nc_msg_type_e evt_type;
	void *data;
} nc_msg_s;

static tem_hnd g_nc_hnd = NULL;
static int g_signal[2]; // send signal to terminate wait handler.
static int g_channel_id; // channel to NIC server

static pthread_mutex_t g_nc_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_api_lock = PTHREAD_MUTEX_INITIALIZER;


#define NC_LOCK(lock)							\
	do {										\
		pthread_mutex_lock(&lock);				\
	} while (0)

#define NC_UNLOCK(lock)							\
	do {										\
		pthread_mutex_unlock(&lock);			\
	} while (0)


#define NC_BUF_SIZE 256

//////////////////////////////////
// Message Handler Function
//////////////////////////////////

static inline nc_msg_s * _nc_create_msg(nc_msg_type_e type, void *data)
{
	nc_msg_s *msg = (nc_msg_s *)malloc(sizeof(nc_msg_s));
	if (!msg) {
		return 0;
	}
	msg->evt_type = type;
	msg->data = data;
}

static inline int32_t _nc_delete_msg(nc_msg_s *msg)
{
	if (!msg) {
		return -1;
	}
	if (msg->data) {
		free(msg->data);
	}
	free(msg);

	return 0;
}

static int32_t _nc_send_msg(nc_msg_type_e type, void *data)
{
	// make message to wait event again
	NIC_ENTRY;
	nc_msg_s *nmsg = _nc_create_msg(type, data);
	if (!nmsg) {
		NIC_ERR;
		return -1;
	}
	tem_msg *msg = (tem_msg *)malloc(sizeof(tem_msg));
	if (!msg) {
		NIC_ERR;
		_nc_delete_msg(nmsg);
		return -1;
	}
	msg->data = nmsg;

	tem_result res = tiny_evtmgr_add_msg(g_nc_hnd, msg, 0);
	if (res != TINY_EVTMGR_SUCCESS) {
		_nc_delete_msg(nmsg);
		free(msg);
		return -1;
	}
	return 0;
}

static void *_nc_init_channel(void *data)
{
	int sock;
	struct sockaddr_in servaddr;
	socklen_t addrlen = sizeof(struct sockaddr_in);

	NIC_ENTRY;

	int32_t res = pipe(g_signal);
	if (res != 0) {
		NIC_ERR;
		return 0;
	}

	sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		NIC_ERR;
		return 0;
	}

	memset(&servaddr, 0, addrlen);
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(NIC_CLIENT_PORT);

	res = bind(sock, (struct sockaddr *)&servaddr, addrlen);
	if (res < 0) {
		NIC_ERR;
		close(sock);
		return 0;
	}

	g_channel_id = sock;

	return 0;
}

static void *_nc_deinit_channel(void *data)
{
	NIC_ENTRY;
	if (g_channel_id != 0) {
		close(g_channel_id);
		g_channel_id = 0;
	}
	if (g_signal[0] != 0) {
		close(g_signal[0]);
		g_signal[0] = 0;
	}
	if (g_signal[1]) {
		close(g_signal[1]);
		g_signal[1] = 0;
	}
}

static void *_nc_receive_message(void *data)
{
	fd_set rfds;
	struct sockaddr_in cliaddr;
	socklen_t addrlen = 0;

	uint8_t buf[NC_BUF_SIZE];
	int sock = g_channel_id;
	int term = g_signal[0];

	NIC_ENTRY;
	FD_ZERO(&rfds);
	FD_SET(sock, &rfds);
	FD_SET(term, &rfds);
	int max = sock > term ? sock + 1 : term + 1;

	int32_t res = select(max + 1, &rfds, 0, 0, 0);
	if (res <= 0) {
		NIC_ERR;
		return 0;
	}
	if (res > 0) {
		if (FD_ISSET(sock, &rfds)) {
			int nbytes = recvfrom(sock, buf, NC_BUF_SIZE, 0, (struct sockaddr *)&cliaddr, &addrlen);
			NIC_LOG("receive message (%d)\n", nbytes);
			if (nbytes < 0) {
				NIC_ERR;
				goto AGAIN;
			} else if (nbytes == 0) {
				NIC_ERR;
				goto AGAIN;
			}
			_nc_handle_msg(buf, nbytes);
		}
		if (FD_ISSET(term, &rfds)) {
			uint8_t buf[3];
			int len = read(term, buf, 3);
			if (len != 3) {
				NIC_ERR;
			}
			if (strcmp(buf, "end") == 0){
				printf("terminate wait thread\n");
				return 0;
			}
		}
	} else {
		assert(0);
	}

AGAIN:
	res = _nc_send_msg(NC_RECEIVE_MSG, 0);
	if (res < 0) {
		NIC_ERR;
	}
	return 0;
}

static int32_t _nc_signal_term(void)
{
	int32_t term = g_signal[1];
	int res = write(term, "end", 3);
	if (res < 0) {
		NIC_ERR;
		return -1;
	}
	return 0;
}

static void *_nc_process(tem_msg *msg)
{
	NIC_ENTRY;
	if (!msg) {
		NIC_ERR;
		return 0;
	}

	nc_msg_s *nmsg = (nc_msg_s *)msg->data;
	if (!nmsg) {
		NIC_ERR;
		return 0;
	}

	switch (nmsg->evt_type) {
	case NC_INIT:
		_nc_init_channel(0);
		break;
	case NC_RECEIVE_MSG:
		_nc_receive_message(0);
		break;
	case NC_DEINIT:
		_nc_deinit_channel(0);
		break;
	default:
		NIC_ERR;
		break;
	}

	_nc_delete_msg(nmsg);
	free(msg);
}


static void *_nc_remove_message(tem_msg *msg)
{
	NIC_ENTRY;
	nc_msg_s *nmsg = (nc_msg_s *)msg->data;
	if (nmsg) {
		_nc_delete_msg(nmsg);
	}
	if (msg) {
		free(msg);
	}
	return 0;
}

/**
 * Public APIs
 */
/*
 * @brief: register the client to get events from a network interface.
 * @details @b #include <>
 *          if there is no client attached then start task
 *          register callback to receive events from the nic server
 *          return handle to distinguish a client
 *          it won't accept duplicated handler.
 * @param[]
 * @return
 * @since
 */
nic_result_s nic_client_register(nic_event_handler handler, void *data, nc_handle *hnd)
{
	NIC_ENTRY;
	tem_result res = TINY_EVTMGR_FAIL;
	NC_LOCK(g_api_lock);

	// add user info to queue
	int32_t nres = _nc_check_dup(handler);
	if (nres != 0) {
		NIC_ERR;
		NC_UNLOCK(g_api_lock);
		return NIC_FAIL;
	}

	struct nc_context *ctx = _nc_list_add(handler, data);
	if (!res) {
		NIC_ERR;
		NC_UNLOCK(g_api_lock);
		return NIC_FAIL;
	}

	*hnd = ctx;

	if (g_nc_hnd == NULL) { // start client task
		res = tiny_evtmgr_init(&g_nc_hnd);
		if (res != TINY_EVTMGR_SUCCESS) {
			NC_UNLOCK(g_api_lock);
			return NIC_FAIL;
		}

		res = tiny_evtmgr_start(g_nc_hnd, _nc_process, _nc_remove_message, 0);
		if (res != TINY_EVTMGR_SUCCESS) {
			goto ERROR_INIT_HANDLER;
		}

		res = _nc_send_msg(NC_INIT, 0);
		if (res < 0) {
			NIC_ERR;
			goto ERROR_RUN_HANDLER;
		}

		res = _nc_send_msg(NC_RECEIVE_MSG, 0);
		if (res < 0) {
			NIC_ERR;
			goto ERROR_RUN_HANDLER;
		}
	}

	NC_UNLOCK(g_api_lock);

	return NIC_SUCCESS;

ERROR_RUN_HANDLER:
	res = tiny_evtmgr_stop(g_nc_hnd);
	if (res != TINY_EVTMGR_SUCCESS) {
		NIC_ERR;
	}
ERROR_INIT_HANDLER:
	res = tiny_evtmgr_deinit(g_nc_hnd);
	if (res != TINY_EVTMGR_SUCCESS) {
		NIC_ERR;
	}
	NC_UNLOCK(g_api_lock);
	return NIC_FAIL;
}


/*
 * @brief: delete client from list
 * @details @b #include <>
 *          remove callback from the list
 *          if there are no clients that are available then terminate a thread
 * @param[]
 * @return if succeed return NIC_SUCCESS
 * @since
 */
nic_result_s nic_client_unregister(nc_handle hnd)
{
	NIC_ENTRY;
	if (!hnd) {
		NIC_ERR;
		return NIC_FAIL;
	}

	NC_LOCK(g_api_lock);
	struct nc_context *ctx = (struct nc_context *)hnd;
	_nc_list_remove(ctx);

	uint32_t empty = _nc_list_empty();
	if (empty) {
		int32_t ret = _nc_signal_term();
		if (ret < 0) {
			NIC_ERR;
			NC_UNLOCK(g_api_lock);
			return NIC_FAIL;
		}
		ret = _nc_send_msg(NC_DEINIT, 0);
		if (ret < 0) {
			NIC_ERR;
			NC_UNLOCK(g_api_lock);
			return NIC_FAIL;
		}

		tem_result res = tiny_evtmgr_stop(g_nc_hnd);
		if (res != TINY_EVTMGR_SUCCESS) {
			NIC_ERR;
			NC_UNLOCK(g_api_lock);
			return NIC_FAIL;
		}

		res = tiny_evtmgr_deinit(g_nc_hnd);
		if (res != TINY_EVTMGR_SUCCESS) {
			NIC_ERR;
			NC_UNLOCK(g_api_lock);
			return NIC_FAIL;
		}
		g_nc_hnd = NULL;
	}

	NC_UNLOCK(g_api_lock);

	return NIC_SUCCESS;
}

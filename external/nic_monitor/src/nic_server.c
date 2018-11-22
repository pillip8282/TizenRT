/****************************************************************************
 *
 * Copyright 2016 Samsung Electronics All Rights Reserved.
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

#ifdef __TIZENRT__
#include <tinyara/config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <tiny_evtmgr.h>
#include <nic_monitor.h>
#include <nic_util.h>

static tem_hnd g_handle;

static int g_sock = -1;
static struct sockaddr_in g_nc_addr;


static int32_t _ns_init(void)
{
	int i = 0;

	g_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (g_sock < 0) {
		NIC_ERR;
		return -1;
	}

	bzero(&g_nc_addr, sizeof(g_nc_addr));
	g_nc_addr.sin_family = AF_INET;
	g_nc_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	g_nc_addr.sin_port = htons(NIC_CLIENT_PORT);

	return 0;
}

static void _ns_deinit(void)
{
	if (g_sock > 0) {
		close(g_sock);
		g_sock = -1;
	}
	return;
}

static void *_ns_remove_message(tem_msg *msg)
{
	nic_msg_s *tmp = msg->data;
	if (tmp && tmp->data) {
		free(tmp->data);
	}
	free(msg->data);
	free(msg);
	return 0;
}

static void *_ns_process(tem_msg *tmsg)
{
	NIC_ENTRY;
	nic_msg_s *msg = tmsg->data;
	if (!msg) {
		NIC_ERR;
		return 0;
	}
	int res = sendto(g_sock, (void *)msg->data, msg->len, 0, (struct sockaddr *)&g_nc_addr, sizeof(g_nc_addr));
	if (res <= 0) {
		NIC_ERR;
		NIC_LOG("res = %d\n", res);
	}
	_ns_remove_message(tmsg);
}

int32_t _nic_dup(nic_msg_s *src_msg, nic_msg_s **dest_msg)
{
	*dest_msg = (nic_msg_s *)malloc(sizeof(nic_msg_s));
	if (!*dest_msg) {
		NIC_ERR;
		return -1;
	}

	(*dest_msg)->len = src_msg->len;
	(*dest_msg)->data = (nic_msg_s *)malloc((*dest_msg)->len);
	if (!((*dest_msg)->data)) {
		NIC_ERR;
		return -1;
	}
	memcpy((*dest_msg)->data, src_msg->data, (*dest_msg)->len);
	return 0;
}


nic_result_s nic_server_start(void)
{
	int32_t res = _ns_init();
	if (res < 0) {
		NIC_ERR;
		return NIC_FAIL;
	}

	// Todo: register lwip netif callback
	tem_result tres = tiny_evtmgr_init(&g_handle);
	if (tres != TINY_EVTMGR_SUCCESS) {
		NIC_ERR;
		goto ERROR;
	}

	tres = tiny_evtmgr_start(g_handle, _ns_process, _ns_remove_message, 0);
	if (tres != TINY_EVTMGR_SUCCESS) {
		NIC_ERR;
		goto ERROR;
	}

	return NIC_SUCCESS;

ERROR:
	_ns_deinit();

	return NIC_FAIL;
}

nic_result_s nic_server_stop(void)
{
	if (!g_handle) {
		NIC_ERR;
		return NIC_FAIL;
	}

	tem_result res = tiny_evtmgr_stop(g_handle);
	if (res != TINY_EVTMGR_SUCCESS) {
		NIC_ERR;
	}

	res = tiny_evtmgr_deinit(g_handle);
	if (res != TINY_EVTMGR_SUCCESS) {
		NIC_ERR;
	}

	_ns_deinit();

	return NIC_SUCCESS;
}

/*
 * @brief: broadcast a message
 * @details @b #include <>
 *          parameter nmsg should be copied when it send to the event handler.
 *          if it is not copied then nmsg could be invalidate when _ns_process() handle it.
 * @param[]
 * @return
 * @since
 */
nic_result_s nic_broadcast_event(nic_msg_s *nmsg)
{
	NIC_ENTRY;
	if (!g_handle) {
		NIC_ERR;
		return NIC_FAIL;
	}
	tem_msg *msg = (tem_msg *)malloc(sizeof(tem_msg));
	if (!msg) {
		NIC_ERR;
		free(nmsg->data);
		free (msg);
		return NIC_FAIL;
	}

	nic_msg_s *dmsg = 0;
	int32_t res = _nic_dup(nmsg, &dmsg);
	if (res < 0) {
		NIC_ERR;
		free(nmsg->data);
		free (msg);
		return NIC_FAIL;
	}

	msg->data = dmsg;

	tem_result tres = tiny_evtmgr_add_msg(g_handle, msg, 0);

	if (tres != TINY_EVTMGR_SUCCESS) {
		return NIC_FAIL;
	}

	return NIC_SUCCESS;
}


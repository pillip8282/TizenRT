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

#ifndef _NIC_SERVER_H__
#define _NIC_SERVER_H__


////////////////////////////////////////////////
//
// Common
//
////////////////////////////////////////////////

typedef enum nic_result_ {
	NIC_SUCCESS,
	NIC_MEM_FAIL,
	NIC_FAIL,
} nic_result_s;

typedef struct _nic_msg{
	int len;
	void *data;
} nic_msg_s;

/* TODO list
 * 1. TYPE of NIC
 * 2. TYPE of EVT
 */

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

/* TODO: Send msg to specific client_handler based on NIC & EVT */


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

/* TODO: Register NIC & EVT type */

#endif

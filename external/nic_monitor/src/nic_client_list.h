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

#ifndef _NIC_CLIENT_LIST_H__
#define _NIC_CLIENT_LIST_H__

#include <stdint.h>
#include <nic_monitor.h>

struct nc_context {
	nic_event_handler handler;
	void *data;
};

struct nc_wrapper {
	struct nc_context item;
	struct nc_wrapper *next;
	nic_type type;
};

struct nc_list {
	struct nc_wrapper *head;
	int cnt;
};

void _nc_list_init(void);
struct nc_context* _nc_list_add(nic_event_handler evt, void *data, nic_type type);
void _nc_list_remove(struct nc_context *info);
int32_t _nc_list_empty(void);
int32_t _nc_check_dup(nic_event_handler func);
void* _nc_list_msg(char *buf, int buflen);

#endif // _NIC_CLIENT_LIST_H__

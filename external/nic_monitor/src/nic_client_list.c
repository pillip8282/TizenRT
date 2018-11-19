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

#include <nic_client_list.h>

#define NC_USER_MAX 16
static uint16_t g_nc_num_list = 0;
static struct nc_context g_nc_list[NC_USER_MAX];

/////////////////
// Queue Function
/////////////////

void _nc_list_init(void)
{
	NIC_ENTRY;
	NC_LOCK(g_nc_lock);
	int i = 0;
	for (i = 0; i < NC_USER_MAX; ++i) {
		g_nc_list[i].handler = 0;
	}
	NC_UNLOCK(g_nc_lock);
}

struct nc_context* _nc_list_add(nic_event_handler evt, void *data)
{
	NIC_ENTRY;
	NC_LOCK(g_nc_lock);
	int i = 0;
	for (i = 0; i < NC_USER_MAX; ++i) {
		if (!g_nc_list[i].handler) {
			g_nc_list[i].handler = evt;
			g_nc_list[i].data = data;
			g_nc_num_list++;
			break;
		}
	}
	if (i == NC_USER_MAX) {
		NIC_ERR;
		return 0;
	}
	NC_UNLOCK(g_nc_lock);

	return &g_nc_list[i];
}

void _nc_list_remove(struct nc_context *info)
{
	NIC_ENTRY;
	NC_LOCK(g_nc_lock);
	int i = 0;
	for (i = 0; i < NC_USER_MAX; ++i) {
		if (&g_nc_list[i] == info) {
			g_nc_list[i].handler = 0;
			g_nc_list[i].data = 0;
			g_nc_num_list--;
			break;
		}
	}
	if (i == NC_USER_MAX) {
		NIC_ERR;
	}
	NC_UNLOCK(g_nc_lock);
}

int32_t _nc_list_empty(void)
{
	return g_nc_num_list == 0 ? 1 : 0;
}

int32_t _nc_check_dup(nic_event_handler func)
{
	NIC_ENTRY;
	if (func == 0) {
		NIC_ERR;
		return 0;
	}

	NC_LOCK(g_nc_lock);
	int i = 0;
	for (i = 0; i < NC_USER_MAX; ++i) {
		if (g_nc_list[i].handler == func) {
			NC_UNLOCK(g_nc_lock);
			return 1;
		}
	}
	NC_UNLOCK(g_nc_lock);
	return 0;
}

void* _nc_list_msg(char *buf, int buflen)
{
	NIC_ENTRY;
	nic_msg_s msg;
	msg.len = buflen;
	msg.data = buf;

	NC_LOCK(g_nc_lock);
	int i = 0;
	for (i = 0; i < NC_USER_MAX; ++i) {
		if (g_nc_list[i].handler) {
			g_nc_list[i].handler(&msg, g_nc_list[i].data);
		}
	}
	NC_UNLOCK(g_nc_lock);

}

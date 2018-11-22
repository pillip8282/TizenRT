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
#include <nic_monitor.h>
#include <nic_client_list.h>
#include <nic_util.h>

struct nc_context;
static struct nc_list g_nc_list;

static pthread_mutex_t g_nc_lock = PTHREAD_MUTEX_INITIALIZER;

#define NC_LOCK(lock)							\
	do {										\
		pthread_mutex_lock(&lock);				\
	} while (0)

#define NC_UNLOCK(lock)							\
	do {										\
		pthread_mutex_unlock(&lock);			\
	} while (0)

/////////////////
// Queue Function
/////////////////

void _nc_list_init(void)
{
	NIC_ENTRY;
	NC_LOCK(g_nc_lock);
	g_nc_list.head = NULL;;
	g_nc_list.cnt = 0;
	NC_UNLOCK(g_nc_lock);
}

struct nc_context* _nc_list_add(nic_event_handler evt, void *data)
{
	NIC_ENTRY;
	NC_LOCK(g_nc_lock);
	struct nc_wrapper *wrapper = (struct nc_wrapper *)malloc(sizeof(struct nc_wrapper));
	wrapper->item.handler = evt;
	wrapper->item.data = data;
	wrapper->next = NULL;

	struct nc_wrapper *cur;
	if (!g_nc_list.head) {
		g_nc_list.head = wrapper;
	} else {
		for (cur = g_nc_list.head; cur->next; cur = cur->next);
		cur->next = wrapper;
	}
	g_nc_list.cnt++;

	NC_UNLOCK(g_nc_lock);


	return &wrapper->item;
}

void _nc_list_remove(struct nc_context *info)
{
	NIC_ENTRY;
	NC_LOCK(g_nc_lock);
	struct nc_wrapper *cur = g_nc_list.head;
	if (&(cur->item) == info) { //head
		g_nc_list.head = cur->next;
		cur->next = NULL;
		free(cur);
	} else {
		for (int i = 1; i < g_nc_list.cnt; i++) {
			if (&(cur->next->item) == info) {
				struct nc_wrapper *tmp = (struct nc_wrapper *)(cur->next)->next;
				free(cur->next);
				cur->next = tmp;
				break;
			}
		}
	}
	g_nc_list.cnt --;
	NC_UNLOCK(g_nc_lock);
}

int32_t _nc_list_empty(void)
{
	return g_nc_list.cnt == 0 ? 1 : 0;
}

int32_t _nc_check_dup(nic_event_handler func)
{
	NIC_ENTRY;
	if (func == 0) {
		NIC_ERR;
		return 0;
	}

	NC_LOCK(g_nc_lock);
	struct nc_wrapper *cur;
	for (cur = g_nc_list.head; cur; cur = cur->next) {
		if (cur->item.handler == func) {
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
	struct nc_wrapper *cur;
	for (cur = g_nc_list.head; cur; cur = cur->next) {
		if (cur->item.handler) {
			cur->item.handler(&msg, cur->item.data);
		}
	}
	NC_UNLOCK(g_nc_lock);

}

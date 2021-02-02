/****************************************************************************
 *
 * Copyright 2021 Samsung Electronics All Rights Reserved.
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

/****************************************************************************
 * Included Files
 ****************************************************************************/
#include <tinyara/config.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>
#include <errno.h>
#include <debug.h>
#include <tinyara/net/if/wifi.h>
#include <tinyara/lwnl/lwnl.h>
#include "vdev_handler.h"

static trwifi_result_e vwifi_handle_init(void *req);
static trwifi_result_e vwifi_handle_deinit(void *req);
static trwifi_result_e vwifi_handle_scanap(void *req);
static trwifi_result_e vwifi_handle_connectap(void *req);
static trwifi_result_e vwifi_handle_disconnectap(void *req);
static trwifi_result_e vwifi_handle_getinfo(void *req);
static trwifi_result_e vwifi_handle_startsta(void *req);
static trwifi_result_e vwifi_handle_startsoftap(void *req);
static trwifi_result_e vwifi_handle_stopsoftap(void *req);
static trwifi_result_e vwifi_handle_setautoconnect(void *req);

trwifi_result_e vwifi_handle_init(void *req)
{
	VWIFI_ENTRY;
	return TRWIFI_SUCCESS;
}

trwifi_result_e vwifi_handle_deinit(void *req)
{
	VWIFI_ENTRY;
	return TRWIFI_SUCCESS;
}

trwifi_result_e vwifi_handle_scanap(void *req)
{
	VWIFI_ENTRY;
	vwifi_create_event(NULL, 2, LWNL_SCAN_DONE);

	return TRWIFI_SUCCESS;
}

trwifi_result_e vwifi_handle_connectap(void *req)
{
	VWIFI_ENTRY;
	vwifi_create_event(NULL, 0, LWNL_STA_CONNECTED);

	return TRWIFI_SUCCESS;
}

trwifi_result_e vwifi_handle_disconnectap(void *req)
{
	VWIFI_ENTRY;
	vwifi_create_event(NULL, 0, LWNL_STA_DISCONNECTED);

	return TRWIFI_SUCCESS;
}

trwifi_result_e vwifi_handle_getinfo(void *req)
{
	VWIFI_ENTRY;
	return TRWIFI_SUCCESS;
}

trwifi_result_e vwifi_handle_startsta(void *req)
{
	VWIFI_ENTRY;
	return TRWIFI_SUCCESS;
}

trwifi_result_e vwifi_handle_startsoftap(void *req)
{
	VWIFI_ENTRY;
	vwifi_create_event(NULL, 1, LWNL_SOFTAP_STA_JOINED);

	return TRWIFI_SUCCESS;
}

trwifi_result_e vwifi_handle_stopsoftap(void *req)
{
	VWIFI_ENTRY;
	vwifi_create_event(NULL, 1, LWNL_SOFTAP_STA_LEFT);

	return TRWIFI_SUCCESS;
}

trwifi_result_e vwifi_handle_setautoconnect(void *req)
{
	VWIFI_ENTRY;
	return TRWIFI_SUCCESS;
}

static struct vwifi_ops g_trwifi_auto = {
	vwifi_handle_init,
	vwifi_handle_deinit,
	vwifi_handle_scanap,
	vwifi_handle_connectap,
	vwifi_handle_disconnectap,
	vwifi_handle_getinfo,
	vwifi_handle_startsta,
	vwifi_handle_startsoftap,
	vwifi_handle_stopsoftap,
	vwifi_handle_setautoconnect,
	NULL
};

struct vwifi_ops *get_vdev_auto(void)
{
	return &g_trwifi_auto;
}

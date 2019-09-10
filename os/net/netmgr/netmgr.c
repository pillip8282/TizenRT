/****************************************************************************
 *
 * Copyright 2019 Samsung Electronics All Rights Reserved.
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

#include <tinyara/config.h>
#include <tinyara/net/netmgr.h>
#include <tinyara/kmalloc.h>
#include <tinyara/lwnl/lwnl80211.h>
#include "netstack.h"

struct tr_netmgr {
	void *dev;
};

static struct tr_netmgr g_netmgr;
/****************************************************************************
 * Name: netmgr_setup
 *
 * Description:
 *   This is called from the OS initialization logic at power-up reset in
 *   order to configure networking data structures.  This is called prior
 *   to platform-specific driver initialization so that the networking
 *   subsystem is prepared to deal with network driver initialization
 *   actions.
 *
 *   Actions performed in this initialization phase assume that base OS
 *   facilities such as semaphores are available but this logic cannot
 *   depend upon OS resources such as interrupts or timers which are not
 *   yet available.
 *
 * Input Parameters:
 *   None
 *
 * Returned Value:
 *   None
 *
 ****************************************************************************/

void netmgr_setup(void *arg)
{
	(void)arg;

	// todo
	if (!g_netmgr.dev) {
		g_netmgr.dev = (void *)kmm_zalloc(sizeof(struct lwnl80211_lowerhalf_s));
		if (!g_netmgr.dev) {
			ndbg("alloc dev fail\n");
		}
	}

	struct netstack *stk = get_netstack();
	int res = stk->ops->init(NULL);
	if (res < 0) {
		ndbg("initialize stack fail\n");
	}

	netdev_mgr_start();
}

/****************************************************************************
 * Name: netmgr_start
 *
 * Description:
 *   This function is called from the OS initialization logic at power-up
 *   reset AFTER initialization of hardware facilities such as timers and
 *   interrupts.   This logic completes the initialization started by
 *   net_setup().
 *
 * Input Parameters:
 *   None
 *
 * Returned Value:
 *   None
 *
 ****************************************************************************/

void netmgr_start(void *arg)
{
	(void)arg;

	int res = lwnl80211_register((struct lwnl80211_lowerhalf_s *)g_netmgr.dev);
	if (res < 0) {
		ndbg("register device fail\n");
	}

	/*  start network stack */
	struct netstack *stk = get_netstack();
	res = stk->ops->start(NULL);
	if (res < 0) {
		ndbg("start stack fail\n");
	}


	return;
}

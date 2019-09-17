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
#include <stdint.h>
#include <errno.h>
#include <tinyara/lwnl/lwnl80211.h>
#include "netdev_mgr_internal.h"

int netdev_lwnlioctl(int cmd, void *arg)
{
	lwnl80211_result_e *res;
	lwnl80211_data *data_in;
	data_in = (lwnl80211_data *)((uintptr_t)arg);
	res = &data_in->res;
	int ret = 0;

	struct netdev *dev = nm_get_netdev((char *)data_in->name);
	if (!dev) {
		return -ENOTTY;
	}

	switch (cmd) {
	case LWNL80211_INIT:
	{
		*res = nm_ifup(dev);
		if (*res != 0) {
			ret = -ENOSYS;
		}
	}
	break;
	case LWNL80211_DEINIT:
	{
		*res = nm_ifdown(dev);
		if (*res != 0) {
			ret = -ENOSYS;
		}
	}
	break;
	case LWNL80211_GET_INFO:
	{
		lwnl80211_info *info = (lwnl80211_info *)data_in->data;
		*res = dev->t_ops.wl.get_info(dev, info);
		if (*res != LWNL80211_SUCCESS) {
			ret = -ENOSYS;
		}
	}
	break;
	case LWNL80211_SET_AUTOCONNECT:
	{

		uint8_t *check = (uint8_t *)data_in->data;
		*res = dev->t_ops.wl.set_autoconnect(dev, *check);
		if (*res != LWNL80211_SUCCESS) {
			ret = -ENOSYS;
		}
	}
	break;
	case LWNL80211_START_STA:
	{
		*res = dev->t_ops.wl.start_sta(dev);
		if (*res != LWNL80211_SUCCESS) {
			ret = -ENOSYS;
		}
	}
	break;
	case LWNL80211_CONNECT_AP:
	{
		lwnl80211_ap_config_s *config = (lwnl80211_ap_config_s *)data_in->data;
		*res = dev->t_ops.wl.connect_ap(dev, config, NULL);
		if (*res != LWNL80211_SUCCESS) {
			ret = -ENOSYS;
		}
	}
	break;
	case LWNL80211_DISCONNECT_AP:
	{
		*res = dev->t_ops.wl.disconnect_ap(dev, NULL);
		if (*res != LWNL80211_SUCCESS) {
			ret = -ENOSYS;
		}
	}
	break;
	case LWNL80211_START_SOFTAP:
	{
		lwnl80211_softap_config_s *config = (lwnl80211_softap_config_s *)(data_in->data);
		*res = dev->t_ops.wl.start_softap(dev, config);
		if (*res != LWNL80211_SUCCESS) {
			ret = -ENOSYS;
		}
	}
	break;
	case LWNL80211_STOP_SOFTAP:
	{
		*res = dev->t_ops.wl.stop_softap(dev);
		if (*res != LWNL80211_SUCCESS) {
			ret = -ENOSYS;
		}
	}
	break;
	case LWNL80211_SCAN_AP:
	{
		*res = dev->t_ops.wl.scan_ap(dev, NULL);
		if (*res != LWNL80211_SUCCESS) {
			ret = -ENOSYS;
		}
	}
	break;
	default:
		ret = -ENOSYS;
		break;
	}
	return ret;
}

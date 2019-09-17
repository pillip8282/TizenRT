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
#ifndef CONFIG_NET_NETMGR
#include <tinyara/lwnl/lwnl80211.h>

int lwnl_ioctl(struct lwnl80211_lowerhalf_s* lower, int cmd, void *arg)
{
	lwnl80211_result_e *res;
	lwnl80211_data *data_in;
	data_in = (lwnl80211_data *)((uintptr_t)arg);
	res = &data_in->res;
	int ret = 0;

	switch (cmd) {
	case LWNL80211_INIT:
	{
		*res = lower->ops->init(NULL);
	}
	break;
	case LWNL80211_DEINIT:
	{
		*res = lower->ops->deinit(NULL);
	}
	break;
	case LWNL80211_GET_INFO:
	{
		lwnl80211_info *info = (lwnl80211_info *)data_in->data;
		*res = lower->ops->get_info(NULL, info);
	}
	break;
	case LWNL80211_SET_AUTOCONNECT:
	{
		uint8_t *check = (uint8_t *)data_in->data;
		*res = lower->ops->set_autoconnect(NULL, *check);
	}
	break;
	case LWNL80211_START_STA:
	{
		*res = lower->ops->start_sta(NULL);
	}
	break;
	case LWNL80211_CONNECT_AP:
	{
		lwnl80211_ap_config_s *config = (lwnl80211_ap_config_s *)data_in->data;
		*res = lower->ops->connect_ap(NULL, config, NULL);
	}
	break;
	case LWNL80211_DISCONNECT_AP:
	{
		*res = lower->ops->disconnect_ap(NULL, NULL);
	}
	break;
	case LWNL80211_START_SOFTAP:
	{
		lwnl80211_softap_config_s *config = (lwnl80211_softap_config_s *)(data_in->data);
		*res = lower->ops->start_softap(NULL, config);
	}
	break;
	case LWNL80211_STOP_SOFTAP:
	{
		*res = lower->ops->stop_softap(NULL);
	}
	break;
	case LWNL80211_SCAN_AP:
	{
		*res = lower->ops->scan_ap(NULL, NULL);
	}
	break;
	default:
		ret = -ENOSYS;
		break;
	}
	if (*res != LWNL80211_SUCCESS) {
		ret = -ENOSYS;
	}

	return ret;
}

#endif

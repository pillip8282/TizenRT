/****************************************************************************
 *
 * Copyright 2020 Samsung Electronics All Rights Reserved.
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
#include <tinyara/wifi/wifi_common.h>
#include <wifi_manager/wifi_manager.h>
#include "wifi_manager_state.h"
#include "wifi_manager_info.h"

struct _wifimgr_info {
	char ssid[WIFIMGR_SSID_LEN + 1];             // SSID of Connected AP if mode is a station
	char softap_ssid[WIFIMGR_SSID_LEN + 1];      // SoftAP SSID if mode is a soft ap
	char mac_address[WIFIMGR_MACADDR_LEN];	   // MAC address of wifi interface
	int rssi;                  // It is only used for a station mode
	// In softAP mode, bssid is a mac address of joined device.
	//                 num is the number of joined device (current system only supports a device).
	// In STA mode, bssid is a mac address of AP
	//                 num is used to check validity of bssid.(if num is 0 then bssid is invalid)
	int num;
	char bssid[WIFIMGR_MACADDR_LEN];
	wifimgr_state_e state;
	wifimgr_state_e prev_state;
};
typedef struct _wifimgr_info _wifimgr_info_s;

static _wifimgr_info_s g_manager_info = {{0}, {0}, {0}, 0};


int wifimgr_get_info(int flag, wifimgr_info_msg_s *info)
{
	if (!(flag & WIFIMGR_SSID)) {
		strncpy(info->ssid, g_manager_info.ssid, WIFIMGR_SSID_LEN);
		info->ssid[WIFIMGR_SSID_LEN] = '\0';
	}

	if (!(flag & WIFIMGR_SOFTAP_SSID)) {
		strncpy(info->softap_ssid, g_manager_info.softap_ssid, WIFIMGR_SSID_LEN);
		info->softap_ssid[WIFIMGR_SSID_LEN] = '\0';
	}

	if (!(flag & WIFIMGR_MACADDR)) {
		memcpy(info->mac_addr, g_manager_info.mac_address, WIFIMGR_MACADDR_LEN);
	}

	if (!(flag & WIFIMGR_RSSI) || !(flag & WIFIMGR_BSSID)) {
		wifi_utils_info_s info_utils;
		wifi_utils_result_e wres = wifi_utils_get_info(&info_utils);
		if (wres == WIFI_UTILS_FAIL) {
			return -1;
		}
		if (!(flag & WIFIMGR_RSSI)) {
			info->rssi = info_utils.rssi;
		}
		if (!(flag & WIFIMGR_BSSID)) {
			if (g_manager_info.state == WIFIMGR_SOFTAP) {
				info->num = info_utils.num;
				if (info->num > 0) {
					memcpy(info->bssid, info_utils.bssid, WIFIMGR_MACADDR_LEN);
				}
			} else if (g_manager_info.state == WIFIMGR_STA_CONNECTED) {
				info->num = 1;
				memcpy(info->bssid, info_utils.bssid, WIFIMGR_MACADDR_LEN);
			} else {
				info->num = 0;
			}
		}
	}

	if (!(flag & WIFIMGR_STATE)) {
		if (g_manager_info.state == WIFIMGR_SCANNING) {
			info->state = g_manager_info.prev_state;
		} else {
			info->state = g_manager_info.state;
		}
	}

	return 0;
}


int wifimgr_set_info(int flag, wifimgr_info_msg_s *info)
{
	if (!(flag & WIFIMGR_SSID)) {
		strncpy(g_manager_info.ssid, info->ssid, WIFIMGR_SSID_LEN);
		g_manager_info.ssid[WIFIMGR_SSID_LEN] = '\0';
	}

	if (!(flag & WIFIMGR_SOFTAP_SSID)) {
		strncpy(g_manager_info.softap_ssid, info->softap_ssid, WIFIMGR_SSID_LEN);
		g_manager_info.softap_ssid[WIFIMGR_SSID_LEN] = '\0';
	}

	if (!(flag & WIFIMGR_MACADDR)) {
		memcpy(g_manager_info.mac_address, info->mac_addr, WIFIMGR_MACADDR_LEN);
	}

	if (!(flag & WIFIMGR_RSSI)) {
		g_manager_info.rssi = info->rssi;
	}

	if (!(flag & WIFIMGR_STATE)) {
		g_manager_info.prev_state = g_manager_info.state;
		g_manager_info.state = info->state;
	}
	return 0;
}


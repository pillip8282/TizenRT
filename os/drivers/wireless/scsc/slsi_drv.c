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

/****************************************************************************
 * Included Files
 ****************************************************************************/
#include <tinyara/config.h>

#include <time.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <semaphore.h>
#include <fcntl.h>
#include <assert.h>
#include <errno.h>
#include <debug.h>

#include <tinyara/kmalloc.h>
#include <tinyara/arch.h>
#include <tinyara/fs/fs.h>
#include <tinyara/sched.h>
#include <tinyara/lwnl/lwnl80211.h>
#include <slsi_wifi/slsi_wifi_api.h>

#define DHCP_RETRY_COUNT           1
#define SLSI_DRV_SCAN_DEBUG        0

/****************************************************************************
 * Private Types
 ****************************************************************************/

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/
#define SLSIDRV_TAG "[SLSIDRV]"

#define SLSIDRV_ERR                                                         \
	do {                                                                    \
		vddbg(SLSIDRV_TAG"[ERR] %s: %d line err(%s)\n",                     \
				  __FILE__, __LINE__, strerror(errno));                     \
	} while (0)

#define SLSIDRV_ENTER                                                       \
	do {                                                                    \
		vddbg(SLSIDRV_TAG"%s:%d\n", __FILE__, __LINE__);                    \
	} while (0)


static WiFi_InterFace_ID_t g_mode;


/*
 * DRIVER SPECIFIC
 */

static void
get_security_type(slsi_security_config_t *sec_modes, uint8_t num_sec_modes,
				   lwnl80211_ap_auth_type_e *auth,
				   lwnl80211_ap_crypto_type_e *crypto)
{
	if (!sec_modes) {
		*auth = LWNL80211_AUTH_OPEN;
		*crypto = LWNL80211_CRYPTO_NONE;
	} else {
		if (sec_modes->secmode == SLSI_SEC_MODE_WEP ||
			sec_modes->secmode == SLSI_SEC_MODE_WEP_SHARED ||
			sec_modes->secmode == (SLSI_SEC_MODE_WEP | SLSI_SEC_MODE_WEP_SHARED)) {
			*auth = LWNL80211_AUTH_WEP_SHARED;
			*crypto = LWNL80211_CRYPTO_WEP_64;
		} else if (num_sec_modes == 2 &&
				   sec_modes[0].secmode == SLSI_SEC_MODE_WPA_MIXED &&
				   sec_modes[1].secmode == SLSI_SEC_MODE_WPA2_MIXED) {
			*auth = LWNL80211_AUTH_WPA_AND_WPA2_PSK;
			*crypto = LWNL80211_CRYPTO_TKIP_AND_AES;
		} else if (sec_modes->secmode == SLSI_SEC_MODE_WPA2_MIXED) {
			*auth = LWNL80211_AUTH_WPA2_PSK;
			*crypto = LWNL80211_CRYPTO_TKIP_AND_AES;
		} else if (sec_modes->secmode == SLSI_SEC_MODE_WPA2_CCMP) {
			*auth = LWNL80211_AUTH_WPA2_PSK;
			*crypto = LWNL80211_CRYPTO_AES;
		} else if (sec_modes->secmode == SLSI_SEC_MODE_WPA2_TKIP) {
			*auth = LWNL80211_AUTH_WPA2_PSK;
			*crypto = LWNL80211_CRYPTO_TKIP;
		} else if (sec_modes->secmode == SLSI_SEC_MODE_WPA_MIXED) {
			*auth = LWNL80211_AUTH_WPA_PSK;
			*crypto = LWNL80211_CRYPTO_TKIP_AND_AES;
		} else if (sec_modes->secmode == SLSI_SEC_MODE_WPA_CCMP) {
			*auth = LWNL80211_AUTH_WPA_PSK;
			*crypto = LWNL80211_CRYPTO_AES;
		} else if (sec_modes->secmode == SLSI_SEC_MODE_WPA_TKIP) {
			*auth = LWNL80211_AUTH_WPA_PSK;
			*crypto = LWNL80211_CRYPTO_TKIP;
		} else {
			*auth = LWNL80211_AUTH_UNKNOWN;
			*crypto = LWNL80211_CRYPTO_UNKNOWN;
		}
	}
}

static void
free_scan_results(lwnl80211_scan_list_s *scan_list)
{
	lwnl80211_scan_list_s *cur = scan_list, *prev = NULL;
	while (cur) {
		prev = cur;
		cur = cur->next;
		free(prev);
	}
	scan_list = NULL;
}

static lwnl80211_result_e
fetch_scan_results(lwnl80211_scan_list_s **scan_list, slsi_scan_info_t **slsi_scan_info)
{
	lwnl80211_result_e result = LWNL80211_FAIL;
	lwnl80211_scan_list_s *cur = NULL, *prev = NULL;
	slsi_scan_info_t *wifi_scan_iter = NULL;
	int cnt = 0;
	if (*slsi_scan_info) {
	/* Initialize pointer */
		wifi_scan_iter = *slsi_scan_info;
		while (wifi_scan_iter) {
#if SLSI_DRV_SCAN_DEBUG
			/* Debug */
			vddbg("SSID (");
			int i = 0;
			for (; i < wifi_scan_iter->ssid_len; i++) {
				vddbg("%c", wifi_scan_iter->ssid[i]);
			}
			vddbg(")\n");
			vddbg("rssi(%d)\n", wifi_scan_iter->rssi);
			vddbg("beacon_period(%d)\n", wifi_scan_iter->beacon_period);
			vddbg("channel(%d)\n", wifi_scan_iter->channel);
			vddbg("physical mode(%d)\n", wifi_scan_iter->phy_mode);
			vddbg("bss type(%d)\n", wifi_scan_iter->bss_type);
			vddbg("wps support(%d)\n", wifi_scan_iter->wps_support);
			vddbg("num_sec modes(%d)\n", wifi_scan_iter->num_sec_modes);
			vddbg("-----------------------------------------------\n");
#endif
			cur = (lwnl80211_scan_list_s *)malloc(sizeof(lwnl80211_scan_list_s));
			if (!cur) {
				free_scan_results(*scan_list);
				return result;
			}
			cur->next = NULL;

			memset(&cur->ap_info, 0x0, sizeof(lwnl80211_ap_scan_info_s));
			cur->ap_info.rssi = wifi_scan_iter->rssi;
			cur->ap_info.channel = wifi_scan_iter->channel;
			if (wifi_scan_iter->phy_mode == 1) {
				cur->ap_info.phy_mode = LWNL80211_IEEE_80211_N;
			} else {
				cur->ap_info.phy_mode = LWNL80211_IEEE_80211_LEGACY;
			}
			get_security_type(wifi_scan_iter->sec_modes, wifi_scan_iter->num_sec_modes,
			&cur->ap_info.ap_auth_type, &cur->ap_info.ap_crypto_type);
			strncpy(cur->ap_info.ssid, (const char *)wifi_scan_iter->ssid, wifi_scan_iter->ssid_len);
			cur->ap_info.ssid_length = (unsigned int)wifi_scan_iter->ssid_len;
			strncpy((char *)cur->ap_info.bssid, (const char *)wifi_scan_iter->bssid, LWNL80211_MACADDR_STR_LEN);
			cur->ap_info.bssid[LWNL80211_MACADDR_STR_LEN] = '\0';

			if (!prev) {
				*scan_list = cur;
			} else {
				prev->next = cur;
			}
			prev = cur;
			wifi_scan_iter = wifi_scan_iter->next;
			cnt++;
		}
		vddbg("%d records scanned\n", cnt);
		result = LWNL80211_SUCCESS;
	} else {
		vddbg("Scanning result is null...\n");
	}
	return result;
}

/*
 * Callback
 */
static int slsi_drv_callback_handler(void *arg)
{
	int *type = (int*)(arg);

	vddbg("Got callback from SLSI drv (%d)\n", status);
	switch (*type) {
	case 1:
		lwnl80211_postmsg(LWNL80211_STA_CONNECTED, NULL);
		break;
	case 2:
		lwnl80211_postmsg(LWNL80211_STA_CONNECT_FAILED, NULL);
		break;
	case 3:
		lwnl80211_postmsg(LWNL80211_SOFTAP_STA_JOINED, NULL);
		break;
	case 4:
		lwnl80211_postmsg(LWNL80211_STA_DISCONNECTED, NULL);
		break;
	case 5:
		lwnl80211_postmsg(LWNL80211_SOFTAP_STA_LEFT, NULL);
		break;
	default:
		lwnl80211_postmsg(LWNL80211_UNKNOWN, NULL);
		break;
	}

	free(type);

	return 0;
}

static void linkup_handler(slsi_reason_t *reason)
{
	int *type = (int *)malloc(sizeof(int));
	if (type == NULL) {
		vddbg("malloc error\n");
		return;
	}

	if (g_mode == SLSI_WIFI_STATION_IF) {
		if (reason->reason_code == SLSI_STATUS_SUCCESS) {
			*type = 1;
		} else {
			*type = 2;
		}
	} else if (g_mode == SLSI_WIFI_SOFT_AP_IF) {
		*type = 3;
	}
	int ret = slsi_drv_callback_handler((void *)type);
	if (ret != 0) {
		vddbg("callback fail(%d)\n", errno);
	}
	free(type);
}

static void linkdown_handler(slsi_reason_t *reason)
{
	int *type = (int *)malloc(sizeof(int));
	if (type == NULL) {
		vddbg("malloc error linkdown\n");
		return;
	}
	*type = 4;
	if (g_mode == SLSI_WIFI_STATION_IF) {
		*type = 4;
	} else if (g_mode == SLSI_WIFI_SOFT_AP_IF) {
		*type = 5;
	}
	int ret = slsi_drv_callback_handler((void *)type);
	if (ret != 0) {
		vddbg("callback fail(%d)\n", errno);
	}
	free(type);
}


static int8_t slsi_drv_scan_callback_handler(slsi_reason_t *reason)
{
	lwnl80211_scan_list_s *scan_list = NULL;

	vddbg("Got scan callback from SLSI drv (%d)\n", status);

	if (reason->reason_code != SLSI_STATUS_SUCCESS) {
		vddbg("Scan failed %d\n");
		lwnl80211_postmsg(LWNL80211_SCAN_FAILED, NULL);
		return SLSI_STATUS_ERROR;
	}

	slsi_scan_info_t *wifi_scan_result;
	int8_t res = WiFiGetScanResults(&wifi_scan_result);
	if (res != SLSI_STATUS_SUCCESS) {
		return SLSI_STATUS_ERROR;
	}

	if (fetch_scan_results(&scan_list, &wifi_scan_result) == LWNL80211_SUCCESS) {
		lwnl80211_postmsg(LWNL80211_SCAN_DONE, (void *)scan_list);
	} else {
		lwnl80211_postmsg(LWNL80211_SCAN_FAILED, NULL);
	}

	WiFiFreeScanResults(&wifi_scan_result);

	return SLSI_STATUS_SUCCESS;
}

/*
 * Interface API
*/
lwnl80211_result_e slsidrv_init(struct netdev *dev)
{
	(void)dev;
	SLSIDRV_ENTER;
	lwnl80211_result_e result = LWNL80211_FAIL;
	if (g_mode == SLSI_WIFI_NONE) {
		int ret = SLSI_STATUS_SUCCESS;
		ret = WiFiStart(SLSI_WIFI_STATION_IF, NULL);
		if (ret != SLSI_STATUS_SUCCESS) {
			vddbg("Failed to start STA mode\n");
			return result;
		}
		g_mode = SLSI_WIFI_STATION_IF;

		ret = WiFiRegisterLinkCallback(&linkup_handler, &linkdown_handler);
		if (ret != SLSI_STATUS_SUCCESS) {
			vddbg("Link callback handles: register failed !\n");
			return result;
		} else {
			vdvdbg("Link callback handles: registered\n");
		}

		ret = WiFiRegisterScanCallback(&slsi_drv_scan_callback_handler);
		if (ret != SLSI_STATUS_SUCCESS) {
			vddbg("[ERR] Register Scan Callback(%d)\n", ret);
			return result;
		}
		result = LWNL80211_SUCCESS;
	} else {
		vddbg("Already %d\n", g_mode);
	}
	return result;
}

lwnl80211_result_e slsidrv_deinit(struct netdev *dev)
{
	(void)dev;
	SLSIDRV_ENTER;
	lwnl80211_result_e result = LWNL80211_FAIL;
	int ret = WiFiStop();
	if (ret == SLSI_STATUS_SUCCESS) {
		g_mode = SLSI_WIFI_NONE;
		result = LWNL80211_SUCCESS;
	} else {
		vddbg("Failed to stop STA mode\n");
	}
	return result;
}

lwnl80211_result_e slsidrv_scan_ap(struct netdev *dev, void *arg)
{
	(void)dev;
	SLSIDRV_ENTER;
	lwnl80211_result_e result = LWNL80211_FAIL;
	int8_t ret = WiFiRegisterScanCallback(&slsi_drv_scan_callback_handler);
	if (ret != SLSI_STATUS_SUCCESS) {
		vddbg("[ERR] Register Scan Callback(%d)\n", ret);
		return result;
	}
	ret = WiFiScanNetwork();
	if (ret != SLSI_STATUS_SUCCESS) {
		vddbg("[ERR] WiFi scan fail(%d)\n", ret);
		return result;
	}
	result = LWNL80211_SUCCESS;
	vddbg("WIFi Scan success\n");
	return result;
}

lwnl80211_result_e slsidrv_connect_ap(struct netdev *dev, lwnl80211_ap_config_s *ap_connect_config, void *arg)
{
	(void)dev;
	SLSIDRV_ENTER;
	lwnl80211_result_e result = LWNL80211_INVALID_ARGS;
	if (!ap_connect_config) {
		return result;
	}

	int ret;
	result = LWNL80211_FAIL;
	slsi_security_config_t *config = NULL;

	if (ap_connect_config->passphrase_length > 0) {
		config = (slsi_security_config_t *)zalloc(sizeof(slsi_security_config_t));
		if (!config) {
			vddbg("Memory allocation failed!\n");
			goto connect_ap_fail;
		}

		if ((ap_connect_config->ap_auth_type == LWNL80211_AUTH_WEP_SHARED) &&
			(ap_connect_config->passphrase_length == 5 || ap_connect_config->passphrase_length == 13)) {
			config->passphrase[0] = '"';
			memcpy(&config->passphrase[1], ap_connect_config->passphrase,
				   ap_connect_config->passphrase_length);
			config->passphrase[ap_connect_config->passphrase_length + 1] = '"';
			config->passphrase[ap_connect_config->passphrase_length + 2] = '\0';
		} else {
			memcpy(config->passphrase, ap_connect_config->passphrase, ap_connect_config->passphrase_length);
		}

		if (ap_connect_config->ap_auth_type == LWNL80211_AUTH_WEP_SHARED) {
			config->secmode = SLSI_SEC_MODE_WEP_SHARED;
		} else if (ap_connect_config->ap_auth_type == LWNL80211_AUTH_WPA_PSK) {
			if (ap_connect_config->ap_crypto_type == LWNL80211_CRYPTO_AES) {
				config->secmode = SLSI_SEC_MODE_WPA_CCMP;
			} else if (ap_connect_config->ap_crypto_type == LWNL80211_CRYPTO_TKIP) {
				config->secmode = SLSI_SEC_MODE_WPA_TKIP;
			} else if (ap_connect_config->ap_crypto_type == LWNL80211_CRYPTO_TKIP_AND_AES) {
				config->secmode = SLSI_SEC_MODE_WPA_MIXED;
			}
		} else if (ap_connect_config->ap_auth_type == LWNL80211_AUTH_WPA2_PSK) {
			if (ap_connect_config->ap_crypto_type == LWNL80211_CRYPTO_AES) {
				config->secmode = SLSI_SEC_MODE_WPA2_CCMP;
			} else if (ap_connect_config->ap_crypto_type == LWNL80211_CRYPTO_TKIP) {
				config->secmode = SLSI_SEC_MODE_WPA2_TKIP;
			} else if (ap_connect_config->ap_crypto_type == LWNL80211_CRYPTO_TKIP_AND_AES) {
				config->secmode = SLSI_SEC_MODE_WPA2_MIXED;
			}
		} else if (ap_connect_config->ap_auth_type == LWNL80211_AUTH_WPA_AND_WPA2_PSK) {
			if (ap_connect_config->ap_crypto_type == LWNL80211_CRYPTO_AES) {
				config->secmode = (SLSI_SEC_MODE_WPA_CCMP | SLSI_SEC_MODE_WPA2_CCMP);
			} else if (ap_connect_config->ap_crypto_type == LWNL80211_CRYPTO_TKIP) {
				config->secmode = (SLSI_SEC_MODE_WPA_TKIP | SLSI_SEC_MODE_WPA2_TKIP);
			} else if (ap_connect_config->ap_crypto_type == LWNL80211_CRYPTO_TKIP_AND_AES) {
				config->secmode = (SLSI_SEC_MODE_WPA_MIXED | SLSI_SEC_MODE_WPA2_MIXED);
			}
		} else {
			/* wrong security type */
			vddbg("Wrong security type\n");
			goto connect_ap_fail;
		}
	} else {
		vddbg("No passphrase!\n");
		goto connect_ap_fail;
	}

	ret = WiFiNetworkJoin((uint8_t *)ap_connect_config->ssid, ap_connect_config->ssid_length, NULL, config);
	if (ret != SLSI_STATUS_SUCCESS) {
		if (ret == SLSI_STATUS_ALREADY_CONNECTED) {
			vdvdbg("WiFiNetworkJoin already connected\n");
			result = LWNL80211_ALREADY_CONNECTED;
		} else {
			vddbg("WiFiNetworkJoin failed: %d, %s\n", ret, ap_connect_config->ssid);
			goto connect_ap_fail;
		}
	} else {
		result = LWNL80211_SUCCESS;
		vdvdbg("Successfully joined the network: %s(%d)\n", ap_connect_config->ssid,
			  ap_connect_config->ssid_length);
	}

connect_ap_fail:
	if (config) {
		free(config);
		config = NULL;
	}

	return result;
}

lwnl80211_result_e slsidrv_disconnect_ap(struct netdev *dev, void *arg)
{
	(void)dev;

	SLSIDRV_ENTER;
	lwnl80211_result_e result = LWNL80211_FAIL;
	int ret = WiFiNetworkLeave();
	if (ret == SLSI_STATUS_SUCCESS) {
		vddbg("WiFiNetworkLeave success\n");
		result = LWNL80211_SUCCESS;
	} else {
		vddbg("WiFiNetworkLeave fail because of %d\n", ret);
	}

	return result;
}

lwnl80211_result_e slsidrv_get_info(struct netdev *dev, lwnl80211_info *wifi_info)
{
	(void)dev;
	SLSIDRV_ENTER;
	lwnl80211_result_e result = LWNL80211_INVALID_ARGS;
	if (wifi_info) {
		result = LWNL80211_FAIL;
		if (g_mode != SLSI_WIFI_NONE) {
			int ret = WiFiGetMac(wifi_info->mac_address);
			if (ret == SLSI_STATUS_SUCCESS) {
				wifi_info->rssi = (int)0;
				if (g_mode == SLSI_WIFI_SOFT_AP_IF) {
					wifi_info->wifi_status = LWNL80211_SOFTAP_MODE;
				} else if (g_mode == SLSI_WIFI_STATION_IF) {
					uint8_t isConnected;
					if (WiFiIsConnected(&isConnected, NULL) == SLSI_STATUS_SUCCESS) {
						int8_t rssi;
						wifi_info->wifi_status = LWNL80211_CONNECTED;
						if (WiFiGetRssi(&rssi) == SLSI_STATUS_SUCCESS) {
							wifi_info->rssi = (int)rssi;
						}
					} else {
						wifi_info->wifi_status = LWNL80211_DISCONNECTED;
					}
				}
				result = LWNL80211_SUCCESS;
			} else {
				vddbg("no MAC exists\n");
			}
		} else {
			vddbg("need to init... get info fail\n");
		}
	}
	return result;
}

lwnl80211_result_e slsidrv_start_softap(struct netdev *dev, lwnl80211_softap_config_s *softap_config)
{
	(void)dev;

	SLSIDRV_ENTER;
	if (!softap_config) {
		return LWNL80211_INVALID_ARGS;
	}

	lwnl80211_result_e ret = LWNL80211_FAIL;
	slsi_ap_config_t *ap_config = NULL;
	slsi_security_config_t *security_config = NULL;

	ap_config = (slsi_ap_config_t *)zalloc(sizeof(slsi_ap_config_t));
	if (!ap_config) {
		vddbg("Memory allocation failed!\n");
		return LWNL80211_FAIL;
	}

	/* add initialization code as slsi_app */
	ap_config->beacon_period = 100;
	ap_config->DTIM = 1;
	ap_config->phy_mode = 1; //1 for 11n, 0 for legacy

	if (softap_config->channel > 14 || softap_config->channel < 1) {
		vddbg("Channel needs to be between 1 and 14" " (highest channel depends on regulatory of countries)\n");
		goto start_soft_ap_fail;
	} else {
		ap_config->channel = softap_config->channel;
	}

	if (softap_config->ssid_length < 1) {
		goto start_soft_ap_fail;
	} else {
		memcpy(&ap_config->ssid, softap_config->ssid, softap_config->ssid_length);
		ap_config->ssid_len = softap_config->ssid_length;
	}

	if (softap_config->passphrase_length < 1) {
		goto start_soft_ap_fail;
	} else {
		security_config = (slsi_security_config_t *)zalloc(sizeof(slsi_security_config_t));
		if (!security_config) {
			vddbg("Memory allocation failed!\n");
			goto start_soft_ap_fail;
		}
		memcpy(security_config->passphrase, softap_config->passphrase, softap_config->passphrase_length);
	}

	if ((softap_config->ap_auth_type == LWNL80211_AUTH_WPA_PSK) &&
		(softap_config->ap_crypto_type == LWNL80211_CRYPTO_TKIP)) {
		security_config->secmode = SLSI_SEC_MODE_WPA_TKIP;
	} else if ((softap_config->ap_auth_type == LWNL80211_AUTH_WPA2_PSK) &&
			   (softap_config->ap_crypto_type == LWNL80211_CRYPTO_AES)) {
		security_config->secmode = SLSI_SEC_MODE_WPA2_CCMP;
	} else if ((softap_config->ap_auth_type == LWNL80211_AUTH_WPA_AND_WPA2_PSK) &&
			   (softap_config->ap_crypto_type == LWNL80211_CRYPTO_TKIP_AND_AES)) {
		security_config->secmode = (SLSI_SEC_MODE_WPA_MIXED | SLSI_SEC_MODE_WPA2_MIXED);
	} else {
		// if not WPA-TKIP, WPA2-AES, WPA/WPA2 TKIP/AES/MIXED, return fail.
		vddbg("Wrong security config. Match proper auth and crypto.\n");
		goto start_soft_ap_fail;
	}
	ap_config->security = security_config;

	if (WiFiStart(SLSI_WIFI_SOFT_AP_IF, ap_config) != SLSI_STATUS_SUCCESS) {
		vddbg("Failed to start AP mode\n");
		goto start_soft_ap_fail;
	}
	g_mode = SLSI_WIFI_SOFT_AP_IF;
	vdvdbg("SoftAP with SSID: %s has successfully started!\n", softap_config->ssid);

	ret = WiFiRegisterLinkCallback(&linkup_handler, &linkdown_handler);
	if (ret != SLSI_STATUS_SUCCESS) {
		vddbg("Link callback handles: register failed !\n");
		return LWNL80211_FAIL;
	} else {
		vdvdbg("Link callback handles: registered\n");
	}

	ret = WiFiRegisterScanCallback(&slsi_drv_scan_callback_handler);
	if (ret != SLSI_STATUS_SUCCESS) {
		vddbg("[ERR] Register Scan Callback(%d)\n", ret);
		return LWNL80211_FAIL;
	}

	ret = LWNL80211_SUCCESS;

start_soft_ap_fail:
	if (ap_config) {
		free(ap_config);
		ap_config = NULL;
	}
	if (security_config) {
		free(security_config);
		security_config = NULL;
	}
	return ret;
}

lwnl80211_result_e slsidrv_start_sta(struct netdev *dev)
{
	(void)dev;

	SLSIDRV_ENTER;
	lwnl80211_result_e result = LWNL80211_FAIL;
	int ret = SLSI_STATUS_SUCCESS;
	ret = WiFiStart(SLSI_WIFI_STATION_IF, NULL);
	if (ret == SLSI_STATUS_SUCCESS) {
		g_mode = SLSI_WIFI_STATION_IF;
		ret = WiFiRegisterLinkCallback(&linkup_handler, &linkdown_handler);
		if (ret == SLSI_STATUS_SUCCESS) {
			vdvdbg("Link callback handles: registered\n");
			ret = WiFiRegisterScanCallback(&slsi_drv_scan_callback_handler);
			if (ret == SLSI_STATUS_SUCCESS) {
				vdvdbg("Scan callback handles: registered\n");
				result = LWNL80211_SUCCESS;
			} else {
				vddbg("[ERR] Register Scan Callback(%d)\n", ret);
			}
		} else {
			vddbg("[ERR] Register Link Callback(%d)\n", ret);
		}
	} else {
		vddbg("Failed to start STA mode\n");
	}
	return result;
}

lwnl80211_result_e slsidrv_stop_softap(struct netdev *dev)
{
	(void)dev;

	SLSIDRV_ENTER;
	lwnl80211_result_e result = LWNL80211_FAIL;
	int ret;
	if (g_mode == SLSI_WIFI_SOFT_AP_IF) {
		ret = WiFiStop();
		if (ret == SLSI_STATUS_SUCCESS) {
			result = LWNL80211_SUCCESS;
			vddbg("Stop AP mode successfully\n");
		} else {
			vddbg("Stop AP mode fail\n");
		}
	} else {
		vddbg("Mode is not AP mode\n");
	}
	return result;
}

lwnl80211_result_e slsidrv_set_autoconnect(struct netdev *dev, uint8_t check)
{
	(void)dev;

	SLSIDRV_ENTER;
	lwnl80211_result_e result = LWNL80211_FAIL;
	int ret = WiFiSetAutoconnect(check);
	if (ret == SLSI_STATUS_SUCCESS) {
		result = LWNL80211_SUCCESS;
		vddbg("External Autoconnect set to %d\n", check);
	} else {
		vddbg("External Autoconnect failed to set %d", check);
	}
	return result;
}

#ifndef CONFIG_NET_NETMGR
static struct lwnl80211_ops g_slsi_ops = {
    slsidrv_init,
    slsidrv_deinit,
    slsidrv_scan_ap,
    slsidrv_connect_ap,
    slsidrv_disconnect_ap,
    slsidrv_get_info,
	slsidrv_start_sta,
    slsidrv_start_softap,
    slsidrv_stop_softap,
    slsidrv_set_autoconnect,
	NULL
};

static struct lwnl80211_lowerhalf_s g_slsi_lower = {
	NULL,
	&g_slsi_ops
};

int slsi_drv_initialize(void)
{
	int res = lwnl80211_register(&g_slsi_lower);
	if (res < 0) {
		ndbg("registering slsi driver to lwnl is fail");
		return -1;
	}
	return 0;
}
#endif

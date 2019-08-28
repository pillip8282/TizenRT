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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <debug.h>
#include <tinyara/lwnl/lwnl80211.h>
#include "wifi_utils.h"

#define WU_INTF_NAME "wlan0"

#define HALF_SECOND_USEC_USEC   500000L

#define WU_TAG "[WU]"

#define WU_ERR										\
	do {											\
		ndbg(WU_TAG"[ERR] %s:%d code(%s)\n",		\
			 __FILE__, __LINE__, strerror(errno));	\
	} while (0)

#define WU_ERR_FD(fd)									\
	do {												\
		ndbg(WU_TAG"[ERR] %s:%d fd(%d) code(%s)\n",		\
			 __FILE__, __LINE__, fd, strerror(errno));	\
	} while (0)

#define WU_CHECK_ERR(arg)						\
	do {										\
		if (arg < 0) {							\
			WU_ERR;								\
			return WIFI_UTILS_FAIL;				\
		}										\
	} while (0)

#define WU_ENTER									\
	do {											\
		ndbg(WU_TAG"%s:%d\n", __FILE__, __LINE__);	\
	} while (0)

#define WU_CALL(fd, code, param)										\
	do {																\
		int res = ioctl(fd, code, (unsigned long)((uintptr_t)&param));	\
		if (res < 0) {													\
			WU_CLOSE(fd);												\
			WU_ERR_FD(fd);												\
			return WIFI_UTILS_FAIL;										\
		}																\
	} while (0)

#define WU_CALL_ERROUT(fd, code, param)									\
	do {																\
		int res = ioctl(fd, code, (unsigned long)((uintptr_t)&param));	\
		if (res < 0) {													\
			WU_ERR;														\
			ret = WIFI_UTILS_FAIL;										\
			goto errout;												\
		}																\
	} while (0)

#define WU_CLOSE(fd)                            \
	do {                                        \
		close(fd);                              \
	} while (0)

static wifi_utils_cb_s g_cbk = {NULL, NULL, NULL, NULL, NULL};

sem_t g_lwnl_signal;

static void _close_cb_handler(void)
{
	int sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sd < 0) {
		WU_ERR;
		return;
	}

	struct sockaddr_in saddr;
	saddr.sin_family = AF_INET;
	saddr.sin_port = 9098;
	saddr.sin_addr.s_addr = inet_addr("127.0.0.1");

	lwnl80211_cb_data data_s = {LWNL80211_EXIT, .u.data = NULL, 0, 0};
	int res = sendto(sd, (const char *)&data_s, sizeof(data_s), 0,
					 (const struct sockaddr *)&saddr, sizeof(saddr));
	if (res < 0) {
		WU_ERR;
		return;
	}

	nvdbg("wait terminate signal\n");
	sem_wait(&g_lwnl_signal);

	return;
}


static void _free_scan_data(wifi_utils_scan_list_s *scan_list)
{
	wifi_utils_scan_list_s *cur = scan_list;
	wifi_utils_scan_list_s *prev = NULL;
	while (cur) {
		prev = cur;
		cur = cur->next;
		free(prev);
	}
	scan_list = NULL;
}

static wifi_utils_result_e _receive_scan_data(int fd, wifi_utils_scan_list_s *scan_list)
{
	int ret;
	int nbytes;
	int cnt = 0;
	int msglen = sizeof(lwnl80211_cb_data);
	wifi_utils_scan_list_s *prev = scan_list;

	while (true) {
		lwnl80211_cb_data msg;
		wifi_utils_scan_list_s *cur = NULL;
		nbytes = read(fd, (char *)&msg, msglen);
		if (nbytes < 0 || nbytes != msglen) {
			ndbg("Failed to receive (nbytes=%d, msglen=%d)\n", nbytes, msglen);
			WU_ERR;
			ret = WIFI_UTILS_FAIL;
			break;
		}

		if (msg.status != LWNL80211_SCAN_DONE) {
			WU_ERR;
			ret =  WIFI_UTILS_FAIL;
			break;
		}

		cur = (wifi_utils_scan_list_s *)malloc(sizeof(wifi_utils_scan_list_s));
		if (!cur) {
			_free_scan_data(scan_list);
			ret = WIFI_UTILS_FAIL;
			break;
		}
		cur->next = NULL;
		memcpy(&(cur->ap_info), &(msg.u.ap_info), sizeof(wifi_utils_ap_scan_info_s));
		cnt++;

		prev->next = cur;
		prev = cur;

		if (msg.md == 0 || cnt >= LWNL80211_MQUEUE_MAX_DATA_NUM) {
			ndbg("End of scanning (%d data)\n", cnt);
			ret = WIFI_UTILS_SUCCESS;
			break;
		}
	}

	return ret;
}

static int _wifi_utils_convert_scan(wifi_utils_scan_list_s **scan_list, void *input, int len)
{
	printf("len(%d)\n", len);
	int remain = len;
	wifi_utils_scan_list_s *prev = NULL;

	while (remain > 0) {
		wifi_utils_scan_list_s *item = (wifi_utils_scan_list_s *)malloc(sizeof(wifi_utils_scan_list_s));
		if (!item) {
			// To Do
			return -1;
		}
		// definition of wifi_utils_scan_list_s and lwnl80211_scan_list shoud be same
		memcpy(&item->ap_info, input, sizeof(wifi_utils_ap_scan_info_s));
		item->next = NULL;

		remain -= sizeof(wifi_utils_ap_scan_info_s);
		input = input + sizeof(wifi_utils_ap_scan_info_s);
		if (!prev) {
			prev = item;
			*scan_list = item;
			continue;
		}
		prev->next = item;
		prev = item;
	}

	return 0;
}


static int _wifi_utils_fetch_event(int fd)
{
	//lwnl80211_cb_data msg;
	//int msglen = sizeof(lwnl80211_cb_data);
	lwnl80211_cb_status status;
	uint32_t len;
	char type_buf[8] = {0,};
	int nbytes = read(fd, (char *)type_buf, 8);

	ndbg("[pkbuild] %s %d\n", __FUNCTION__, nbytes);

	if (nbytes < 0) {
		ndbg("Failed to receive (nbytes=%d, msglen=%d)\n", nbytes, msglen);
		WU_ERR;
		return -1;
	}

	memcpy(&status, type_buf, sizeof(lwnl80211_cb_status));
	memcpy(&len, type_buf + sizeof(lwnl80211_cb_status), sizeof(uint32_t));

	ndbg("[pkbuild] %d %d\n", status, len);

	switch (status) {
	case LWNL80211_STA_CONNECTED:
		g_cbk.sta_connected(WIFI_UTILS_SUCCESS, NULL);
		break;
	case LWNL80211_STA_CONNECT_FAILED:
		g_cbk.sta_connected(WIFI_UTILS_FAIL, NULL);
		break;
	case LWNL80211_STA_DISCONNECTED:
		g_cbk.sta_disconnected(NULL);
		break;
	case LWNL80211_SOFTAP_STA_JOINED:
		g_cbk.softap_sta_joined(NULL);
		break;
	case LWNL80211_SOFTAP_STA_LEFT:
		g_cbk.softap_sta_left(NULL);
		break;
	case LWNL80211_SCAN_FAILED:
		g_cbk.scan_done(WIFI_UTILS_FAIL, NULL, NULL);
		break;
	case LWNL80211_SCAN_DONE:
	{
		char *buf = (char *)malloc(len);
		if (!buf) {
			g_cbk.scan_done(WIFI_UTILS_FAIL, NULL, NULL);
			// todo cancel pool or do it again??
			break;
		}
		ndbg("[pkbuild] read scan data \n");
		int res = read(fd, buf, len);
		ndbg("[pkbuild] readed scan data(%d)\n", res);
		if (res != len) {
			ndbg("read error\n");
			free(buf);
			g_cbk.scan_done(WIFI_UTILS_FAIL, NULL, NULL);
			// todo cancel pool or do it again??
			break;
		}
		wifi_utils_scan_list_s *scan_list = NULL;
		res = _wifi_utils_convert_scan(&scan_list, buf, len);
		if (res < 0) {
			// To Do
			g_cbk.scan_done(WIFI_UTILS_FAIL, NULL, NULL);
		}
		g_cbk.scan_done(WIFI_UTILS_SUCCESS, scan_list, 0);
		free(buf);
		break;
	}
	default:
		ndbg("Bad status received (%d)\n", msg.status);
		WU_ERR;
		return -1;
	}
	return 0;
}

static int _wifi_utils_callback_handler(int argc, char *argv[])
{
	WU_ENTER;
	ndbg("run utils callback handler (should be moved to booting)\n");
	fd_set rfds, ofds;

	int nd = socket(AF_LWNL, SOCK_RAW, LWNL_ROUTE);
	if (nd < 0) {
		WU_ERR;
		return -1;
	}

	int sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sd < 0) {
		WU_ERR;
		close(nd);
		return -1;
	}
	struct sockaddr_in saddr;
	memset(&saddr, 0, sizeof(struct sockaddr));
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = htonl(INADDR_ANY);
	saddr.sin_port = 9098;

	int res = bind(sd, (struct sockaddr *)&saddr, sizeof(struct sockaddr));
	if (res < 0) {
		WU_ERR;
		close(nd);
		close(sd);
		return -1;
	}

	FD_ZERO(&ofds);
	FD_SET(nd, &ofds);
	FD_SET(sd, &ofds);

	int maxfd = (nd > sd) ? (nd + 1) : (sd + 1);

	// notify initialization of receive handler is done
	sem_post(&g_lwnl_signal);

	while (1) {
		rfds = ofds;
		printf("[pkbuild] wait\n");
		res = select(maxfd, &rfds, NULL, NULL, NULL);
		printf("[pkbuild] get event(%d)\n", res);
		if (res < 0) {
			WU_ERR;
			break;
		}

		if (res == 0) {
			WU_ERR;
			break;
		}

		if (FD_ISSET(nd, &rfds)) {
			// get events from netlink driver
			res = _wifi_utils_fetch_event(nd);
			if (res < 0) {
				ndbg("message currupted\n");
				break;
			}
		} else if (FD_ISSET(sd, &rfds)) {
			// get terminate event from application
			nvdbg("get terminate message\n");
			sem_post(&g_lwnl_signal);
			break;
		} else {
			// unknown error
			WU_ERR;
			break;
		}
	}

	close(nd);
	close(sd);
	return 0;
}


wifi_utils_result_e wifi_utils_init(void)
{
	WU_ENTER;

	wifi_utils_result_e ret = WIFI_UTILS_FAIL;

	int fd = socket(AF_LWNL, SOCK_RAW, LWNL_ROUTE);
	WU_CHECK_ERR(fd);

	/* Start to send ioctl */
	lwnl80211_data data_in = {NULL, 0, 0, WU_INTF_NAME};

	WU_CALL_ERROUT(fd, LWNL80211_INIT, data_in);

	WU_CLOSE(fd);

	sem_init(&g_lwnl_signal, 0, 0);

	int tid = task_create("lwnl8021 cb handler", 110, 4096, (main_t)_wifi_utils_callback_handler, NULL);
	if (tid < 0) {
		WU_ERR;
		goto errout;
	}

	sem_wait(&g_lwnl_signal);

	return WIFI_UTILS_SUCCESS;

errout:
	WU_CLOSE(fd);

	return ret;
}

wifi_utils_result_e wifi_utils_deinit(void)
{
	WU_ENTER;

	int fd = socket(AF_LWNL, SOCK_RAW, LWNL_ROUTE);
	WU_CHECK_ERR(fd);
	lwnl80211_data data_in = {NULL, 0, 0, WU_INTF_NAME};
	WU_CALL(fd, LWNL80211_DEINIT, data_in);
	WU_CLOSE(fd);

	g_cbk = (wifi_utils_cb_s){NULL, NULL, NULL, NULL, NULL};
	_close_cb_handler();

	sem_destroy(&g_lwnl_signal);

	return WIFI_UTILS_SUCCESS;
}

wifi_utils_result_e wifi_utils_scan_ap(void *arg)
{
	WU_ENTER;

	int fd = socket(AF_LWNL, SOCK_RAW, LWNL_ROUTE);
	WU_CHECK_ERR(fd);

	lwnl80211_data data_in = {NULL, 0, 0, WU_INTF_NAME};

	WU_CALL(fd, LWNL80211_SCAN_AP, data_in);

	WU_CLOSE(fd);

	return WIFI_UTILS_SUCCESS;
}


wifi_utils_result_e wifi_utils_register_callback(wifi_utils_cb_s *cbk)
{
	wifi_utils_result_e wuret = WIFI_UTILS_INVALID_ARGS;
	if (cbk) {
		g_cbk = *cbk;
		wuret = WIFI_UTILS_SUCCESS;
	} else {
		ndbg("WiFi callback register failure (no callback)\n");
	}
	return wuret;
}


wifi_utils_result_e wifi_utils_connect_ap(wifi_utils_ap_config_s *ap_connect_config, void *arg)
{
	WU_ENTER;

	int fd = socket(AF_LWNL, SOCK_RAW, LWNL_ROUTE);
	WU_CHECK_ERR(fd);

	lwnl80211_data data_in = {(void *)ap_connect_config, sizeof(wifi_utils_ap_config_s), 0, WU_INTF_NAME};

	WU_CALL(fd, LWNL80211_CONNECT_AP, data_in);

	WU_CLOSE(fd);

	return WIFI_UTILS_SUCCESS;
}


wifi_utils_result_e wifi_utils_disconnect_ap(void *arg)
{
	WU_ENTER;

	int fd = socket(AF_LWNL, SOCK_RAW, LWNL_ROUTE);
	WU_CHECK_ERR(fd);

	lwnl80211_data data_in = {NULL, 0, 0, WU_INTF_NAME};

	WU_CALL(fd, LWNL80211_DISCONNECT_AP, data_in);

	WU_CLOSE(fd);

	return WIFI_UTILS_SUCCESS;
}


wifi_utils_result_e wifi_utils_get_info(wifi_utils_info_s *wifi_info)
{
	WU_ENTER;

	int fd = socket(AF_LWNL, SOCK_RAW, LWNL_ROUTE);
	WU_CHECK_ERR(fd);

	lwnl80211_data data_in = {(void *)wifi_info, sizeof(wifi_utils_info_s), 0, WU_INTF_NAME};

	WU_CALL(fd, LWNL80211_GET_INFO, data_in);

	WU_CLOSE(fd);

	return WIFI_UTILS_SUCCESS;
}


wifi_utils_result_e wifi_utils_start_softap(wifi_utils_softap_config_s *softap_config)
{
	WU_ENTER;

	int fd = socket(AF_LWNL, SOCK_RAW, LWNL_ROUTE);
	WU_CHECK_ERR(fd);

	lwnl80211_data data_in = {(void *)softap_config, sizeof(wifi_utils_softap_config_s), 0, WU_INTF_NAME};

	WU_CALL(fd, LWNL80211_START_SOFTAP, data_in);

	WU_CLOSE(fd);

	return WIFI_UTILS_SUCCESS;
}


wifi_utils_result_e wifi_utils_start_sta(void)
{
	WU_ENTER;

	int fd = socket(AF_LWNL, SOCK_RAW, LWNL_ROUTE);
	WU_CHECK_ERR(fd);

	lwnl80211_data data_in = {NULL, 0, 0, WU_INTF_NAME};

	WU_CALL(fd, LWNL80211_START_STA, data_in);

	WU_CLOSE(fd);

	return WIFI_UTILS_SUCCESS;
}


wifi_utils_result_e wifi_utils_stop_softap(void)
{
	WU_ENTER;

	int fd = socket(AF_LWNL, SOCK_RAW, LWNL_ROUTE);
	WU_CHECK_ERR(fd);

	lwnl80211_data data_in = {NULL, 0, 0, WU_INTF_NAME};

	WU_CALL(fd, LWNL80211_STOP_SOFTAP, data_in);

	WU_CLOSE(fd);

	return WIFI_UTILS_SUCCESS;
}


wifi_utils_result_e wifi_utils_set_autoconnect(uint8_t check)
{
	WU_ENTER;

	int fd = socket(AF_LWNL, SOCK_RAW, LWNL_ROUTE);
	WU_CHECK_ERR(fd);

	uint8_t *chk = &check;
	lwnl80211_data data_in = {(void *)chk, sizeof(uint8_t), 0, WU_INTF_NAME};

	WU_CALL(fd, LWNL80211_SET_AUTOCONNECT, data_in);

	WU_CLOSE(fd);

	return WIFI_UTILS_SUCCESS;
}

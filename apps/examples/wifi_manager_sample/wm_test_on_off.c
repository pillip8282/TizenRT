/****************************************************************************
 *
 * Copyright 2020 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License\n");
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
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <semaphore.h>
#include <errno.h>
//#include <tinyara/fs/ioctl.h>
#include <sys/boardctl.h>
#include <pthread.h>
#include <wifi_manager/wifi_manager.h>
#include "wm_test.h"

/*
 * Macro
 */
#define WM_AP_SSID         CONFIG_WIFIMANAGER_TEST_AP_SSID
#define WM_AP_PASSWORD     CONFIG_WIFIMANAGER_TEST_AP_PASSPHRASE
#define WM_AP_AUTH         CONFIG_WIFIMANAGER_TEST_AP_AUTHENTICATION
#define WM_AP_CRYPTO       CONFIG_WIFIMANAGER_TEST_AP_CRYPTO
#define WM_TEST_TRIAL	   CONFIG_WIFIMANAGER_TEST_TRIAL
#define WM_SOFTAP_SSID     CONFIG_WIFIMANAGER_TEST_SOFTAP_SSID
#define WM_SOFTAP_PASSWORD CONFIG_WIFIMANAGER_TEST_SOFTAP_PASSWORD
#define WM_SOFTAP_CHANNEL  CONFIG_WIFIMANAGER_TEST_SOFTAP_CHANNEL

#define WIFIMGR_SSID ""
#define WIFIMGR_PWD ""
#define WIFIMGR_AUTH WIFI_MANAGER_AUTH_WPA2_PSK
#define WIFIMGR_CRYPTO WIFI_MANAGER_CRYPTO_AES

static sem_t g_wm_sem = SEM_INITIALIZER(0);
#define WO_TEST_SIGNAL								\
	do {											\
		printf("[WO] T%d send signal\t %s:%d\n", getpid(), __FUNCTION__, __LINE__); \
		sem_post(&g_wm_sem);						\
	} while (0)

#define WO_TEST_WAIT								\
	do {											\
		printf("[WO] T%d wait signal\t %s:%d\n", getpid(), __FUNCTION__, __LINE__); \
		sem_wait(&g_wm_sem);                        \
	} while (0)

#define WO_ERROR(res) printf("[WOERR] code(%d), %s\t%s:%d\n",\
							 res, __FUNCTION__, __FILE__, __LINE__)

#define WO_CONN_FAIL 1
#define WO_CONN_SUCCESS 2
#define WO_INTERVAL 2
#define WO_WAIT_CONN_TIME 10
#define WO_CONNECT_WAIT 130
#define WO_RESET_PERIOD 10
/*
 * callbacks
 */
static void wm_sta_connected(wifi_manager_result_e);
static void wm_sta_disconnected(wifi_manager_disconnect_e);
static void wm_softap_sta_join(void);
static void wm_softap_sta_leave(void);
static void wm_scan_done(wifi_manager_scan_info_s **scan_result, wifi_manager_scan_result_e res);

/*
 * State
 */
//static int run_init(int argc, char *argv[]);
static int run_init(void *arg);
static int run_connecting(wifi_manager_ap_config_s *ap_config);
static int run_connected(void);
/*
 * Global
 */
static wifi_manager_cb_s g_wifi_callbacks = {
	wm_sta_connected,
	wm_sta_disconnected,
	wm_softap_sta_join,
	wm_softap_sta_leave,
	wm_scan_done,
};

static int g_conn_res = 0;
int g_wo_test_value = 0;
int g_wo_cnt_auto_connect = 0;

/*
 * Callback
 */
void wm_sta_connected(wifi_manager_result_e res)
{
	printf("[WO] T%d --> %s res(%d)\n", getpid(), __FUNCTION__, res);
	if (WIFI_MANAGER_SUCCESS == res) {
		g_conn_res = WO_CONN_SUCCESS;
	} else {
		g_conn_res = WO_CONN_FAIL;
	}
	WO_TEST_SIGNAL;
}


void wm_sta_disconnected(wifi_manager_disconnect_e disconn)
{
	printf("[WO] T%d --> %s %d\n", getpid(), __FUNCTION__, disconn);
	g_conn_res = WO_CONN_FAIL;
	WO_TEST_SIGNAL;
}


void wm_softap_sta_join(void)
{
	printf("[WO] T%d --> %s\n", getpid(), __FUNCTION__);
	WO_TEST_SIGNAL;
}


void wm_softap_sta_leave(void)
{
	printf("[WO] T%d --> %s\n", getpid(), __FUNCTION__);
	WO_TEST_SIGNAL;
}


void wm_scan_done(wifi_manager_scan_info_s **scan_result, wifi_manager_scan_result_e res)
{
	printf("[WO] T%d --> %s\n", getpid(), __FUNCTION__);
	/* Make sure you copy the scan results onto a local data structure.
	 * It will be deleted soon eventually as you exit this function.
	 */
	if (scan_result == NULL) {
		WO_TEST_SIGNAL;
		return;
	}
	wifi_manager_scan_info_s *wifi_scan_iter = *scan_result;
	while (wifi_scan_iter != NULL) {
		printf("[WO] WiFi AP SSID: %-20s, WiFi AP BSSID: %-20s, WiFi Rssi: %d, AUTH: %d, CRYPTO: %d\n",
			   wifi_scan_iter->ssid, wifi_scan_iter->bssid, wifi_scan_iter->rssi,
			   wifi_scan_iter->ap_auth_type, wifi_scan_iter->ap_crypto_type);
		wifi_scan_iter = wifi_scan_iter->next;
	}
	WO_TEST_SIGNAL;
}

static void print_wifi_ap_profile(wifi_manager_ap_config_s *config, char *title)
{
	printf("====================================\n");
	if (title) {
		printf("[WO] %s\n", title);
	}
	printf("------------------------------------\n");
	printf("SSID: %s\n", config->ssid);
	printf("security type (%d) (%d)\n", config->ap_auth_type, config->ap_crypto_type);
	printf("====================================\n");
}

static pthread_t g_wo_pid;
static int g_wo_check = 0;
char g_wo_ssid[100] = {0,};
char g_wo_auth[100] = {0,};
char g_wo_pass[100] = {0,};
int g_wo_wait_time = 0;

static void *_connect_timer(pthread_addr_t pvarg)
{
	printf("[pkbuild] wait %d %s:%d\n", g_wo_wait_time
		   , __FUNCTION__, __LINE__);
	sleep(g_wo_wait_time);
	if (g_wo_check == 0) {
		// reboot
		printf("[pkbuild] try again\n");
		boardctl(BOARDIOC_RESET, 0);
		//assert(0);
	}
	printf("[pkbuild] %s:%d\n", __FUNCTION__, __LINE__);

	return NULL;
}

static int start_watchdog(void)
{
	printf("[pkbuild] start timer\n");
	g_wo_check = 0;
	FILE *fp = fopen("/mnt/test.txt", "w");
	if (!fp) {
		return -1;
	}
	char space[2] = " ";
	char tmp[10] = {0,};
	sprintf(tmp, "%d", g_wo_cnt_auto_connect);

	printf("g_wo_ssid (%s)\n", g_wo_ssid);
	printf("g_wo_auth (%s)\n", g_wo_auth);
	printf("g_wo_pass (%s)\n", g_wo_pass);
	fwrite(g_wo_ssid, 1, strlen(g_wo_ssid), fp);
	fwrite(space, 1, 1, fp);
	fwrite(g_wo_auth, 1, strlen(g_wo_auth), fp);
	fwrite(space, 1, 1, fp);
	fwrite(g_wo_pass, 1, strlen(g_wo_pass), fp);
	fwrite(space, 1, 1, fp);
	fwrite(tmp, 1, strlen(tmp), fp);

	fclose(fp);

	int res = pthread_create(&g_wo_pid, NULL, _connect_timer, NULL);
	if (res < 0) {
		printf("create pthread fail\n");
		return -1;
	}
	return 0;
}

static int terminate_watchdog(void)
{
	printf("[pkbuild] end timer\n");
	g_wo_check = 1;
	remove("/mnt/test.txt");
	pthread_join(g_wo_pid, 0);

	return 0;
}

static void reset_board(void)
{
	printf("\n\n\n");
	printf("[pkbuild] try again2\n");
	printf("\n\n\n");

	FILE *fp = fopen("/mnt/test.txt", "w");
	if (!fp) {
		WO_ERROR(errno);
		return;
	}
	char space[2] = " ";
	char tmp[10] = {0,};
	sprintf(tmp, "%d", g_wo_cnt_auto_connect);

	printf("g_wo_ssid (%s)\n", g_wo_ssid);
	printf("g_wo_auth (%s)\n", g_wo_auth);
	printf("g_wo_pass (%s)\n", g_wo_pass);
	fwrite(g_wo_ssid, 1, strlen(g_wo_ssid), fp);
	fwrite(space, 1, 1, fp);
	fwrite(g_wo_auth, 1, strlen(g_wo_auth), fp);
	fwrite(space, 1, 1, fp);
	fwrite(g_wo_pass, 1, strlen(g_wo_pass), fp);
	fwrite(space, 1, 1, fp);
	fwrite(tmp, 1, strlen(tmp), fp);

	fclose(fp);

	printf("try world\n");

	boardctl(BOARDIOC_RESET, 0);

	printf("<--try world\n");
	//assert(0);
}

//static int run_init(int argc, char *argv[])
static void wm_get_info(wifi_manager_ap_config_s *arg)
{
	printf("[WO] T%d -->%s\n", getpid(), __FUNCTION__);
	wifi_manager_ap_config_s apconfig;
	wifi_manager_result_e res = wifi_manager_get_config(&apconfig);
	if (res != WIFI_MANAGER_SUCCESS) {
		printf("[WO] Get AP configuration failed\n");
		return;
	}
	print_wifi_ap_profile(&apconfig, "Stored Wi-Fi Information");
}

static int run_connecting(wifi_manager_ap_config_s *ap_config)
{
	printf("[WO] -->%s\n", __FUNCTION__);

	g_wo_wait_time = WO_WAIT_CONN_TIME;
	start_watchdog();

	wifi_manager_result_e res = wifi_manager_connect_ap(ap_config);
	if (res != WIFI_MANAGER_SUCCESS) {
		WO_ERROR(res);
		goto connect_fail;
	}

	if (g_wo_test_value == 1) {
		printf("[pkbuild] test sleep 50\n");
		sleep(50);
		g_wo_test_value = 0;
	}

	WO_TEST_WAIT;

	printf("[WO] receive signal\n");
	terminate_watchdog();
	printf("<-- terminate\n");
	if (g_conn_res == WO_CONN_FAIL) {
		// does it need to get info from wi-fi wm_get_info(ap_config);
		goto connect_fail;
	} else if (g_conn_res == WO_CONN_SUCCESS) {
		return 2; // connected, wait disconnect message
	} else {
		printf("[WO] program is corrupted %s\n", __FUNCTION__);
		reset_board();
		//assert(0);
	}
	return 0;

connect_fail:
	printf("[WO] wait %d second\n", WO_INTERVAL);
	sleep(WO_INTERVAL);
	return 1;
}

static int run_connected(void)
{
	printf("[WO] -->%s\n", __FUNCTION__);
	struct timespec abstime;
	int ret_chk = clock_gettime(CLOCK_REALTIME, &abstime);
	if (ret_chk) {
		printf("get clock time fail\n");
		reset_board();
	}

	abstime.tv_sec = abstime.tv_sec + WO_CONNECT_WAIT;
	abstime.tv_nsec = 0;

	int res = sem_timedwait(&g_wm_sem, &abstime);
	if (res < 0) {
		if (errno == ETIMEDOUT) {
			printf("timeout\n");
			reset_board();
		}
	}

	if (g_conn_res == WO_CONN_FAIL) {
		if ((g_wo_cnt_auto_connect % WO_RESET_PERIOD) == 0) {
		//if ((g_wo_cnt_auto_connect == 1)){

			reset_board();
		}
		return 1;
	} else {
		printf("[WO] program is corrupted %s\n", __FUNCTION__);
		reset_board();
		//assert(0);
	}
	return 0;
}

static int run_init(void *arg)
{
	wifi_manager_result_e res = wifi_manager_init(&g_wifi_callbacks);
	if (res != WIFI_MANAGER_SUCCESS) {
		WO_ERROR(res);
		return -1;
	}

	/* Set AP Configuration */
	struct options *ap_info = (struct options *)arg;
	wifi_manager_ap_config_s apconfig;
	strncpy(apconfig.ssid, ap_info->ssid, WIFIMGR_SSID_LEN);
	apconfig.ssid_length = strlen(ap_info->ssid);
	apconfig.ssid[WIFIMGR_SSID_LEN] = '\0';
	apconfig.ap_auth_type = ap_info->auth_type;
	if (ap_info->auth_type != WIFI_MANAGER_AUTH_OPEN) {
		strncpy(apconfig.passphrase, ap_info->password, WIFIMGR_PASSPHRASE_LEN);
		apconfig.passphrase[WIFIMGR_PASSPHRASE_LEN] = '\0';
		apconfig.passphrase_length = strlen(ap_info->password);
		apconfig.ap_crypto_type = ap_info->crypto_type;
	} else {
		apconfig.passphrase[0] = '\0';
		apconfig.passphrase_length = 0;
		apconfig.ap_crypto_type = ap_info->crypto_type;
	}

	print_wifi_ap_profile(&apconfig, "Connecting AP Info");

	/*  Run Auto Test */
	int state = 1;
	while (1) {
		if (state == 1) {
			state = run_connecting(&apconfig);
		} else if (state == 2) {
			g_wo_cnt_auto_connect++;
			printf("\n\n\n");
			printf("[WO] connection count %d\n", g_wo_cnt_auto_connect);
			printf("\n\n\n");
			state = run_connected();
		}
	}

	printf("[WO] terminate program total (%d)\n", g_wo_cnt_auto_connect);
	return 0;
}

//static const char *g_argv[3];
//static wifi_manager_ap_config_s g_apconfig;

void wm_test_on_off(void *arg)
{
	run_init(arg);
}

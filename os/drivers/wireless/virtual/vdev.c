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

#include <time.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <semaphore.h>
#include <fcntl.h>
#include <errno.h>
#include <debug.h>

#include <net/if.h>
#include <tinyara/lwnl/lwnl.h>
#include <tinyara/kthread.h>
#include <tinyara/netmgr/netdev_mgr.h>
#include <tinyara/net/if/wifi.h>
#include "vdev_handler.h"

#define VWIFI_MSG_QUEUE_NAME "/dev/vwifi"

/****************************************************************************
 * Private Types
 ****************************************************************************/
static trwifi_result_e vdev_init(struct netdev *dev);
static trwifi_result_e vdev_deinit(struct netdev *dev);
static trwifi_result_e vdev_scan_ap(struct netdev *dev, trwifi_ap_config_s *config);
static trwifi_result_e vdev_connect_ap(struct netdev *dev, trwifi_ap_config_s *ap_connect_config, void *arg);
static trwifi_result_e vdev_disconnect_ap(struct netdev *dev, void *arg);
static trwifi_result_e vdev_get_info(struct netdev *dev, trwifi_info *wifi_info);
static trwifi_result_e vdev_start_softap(struct netdev *dev, trwifi_softap_config_s *softap_config);
static trwifi_result_e vdev_start_sta(struct netdev *dev);
static trwifi_result_e vdev_stop_softap(struct netdev *dev);
static trwifi_result_e vdev_set_autoconnect(struct netdev *dev, uint8_t check);

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/
static struct trwifi_ops g_trwifi_drv_ops = {
	vdev_init,                   /* init */
	vdev_deinit,                 /* deinit */
	vdev_scan_ap,                /* scan_ap */
	vdev_connect_ap,             /* connect_ap */
	vdev_disconnect_ap,          /* disconnect_ap */
	vdev_get_info,               /* get_info */
	vdev_start_sta,              /* start_sta */
	vdev_start_softap,           /* start_softap */
	vdev_stop_softap,            /* stop_softap */
	vdev_set_autoconnect,        /* set_autoconnect */
	NULL                              /* drv_ioctl */
};

static struct netdev *g_vwifi_dev = NULL;
static uint8_t g_hwaddr[IFHWADDRLEN] = {0x0e, 0x04, 0x96, 0x1d, 0xb3, 0xb0};

extern void vwifi_handle_packet(uint8_t *buf, uint32_t len);
extern void vwifi_initialize_scan(void);
/*
 * Callback
 */
static inline int _create_message(struct vwifi_msg **vmsg, struct vwifi_req *req)
{
	struct vwifi_msg *tmsg = (struct vwifi_msg *)kmm_malloc(sizeof(struct vwifi_msg));
	if (!tmsg) {
		VWIFI_ERROR(0);
		return -1;
	}
	sem_t *signal = (sem_t *)kmm_malloc(sizeof(sem_t));
	if (!signal) {
		kmm_free(tmsg);
		VWIFI_ERROR(0);
		return -1;
	}
	sem_init(signal, 0, 0);

	tmsg->req = req;
	tmsg->signal = signal;

	*vmsg = tmsg;

	return 0;
}

static inline int _destroy_message(struct vwifi_msg *msg)
{
	if (msg) {
		if (msg->signal) {
			sem_destroy(msg->signal);
			kmm_free(msg->signal);
		}
		kmm_free(msg);
	}

	return 0;
}

static inline void _wait_message(struct vwifi_msg *msg) {
	int res = sem_wait(msg->signal);
	if (res < 0){
		VWIFI_ERROR(res);
	}
}

static inline void _send_signal(struct vwifi_msg *msg) {
	int res = sem_post(msg->signal);
	if (res < 0) {
		VWIFI_ERROR(res);
	}
}

static inline int _recv_message(int fd, char *buf, int buflen)
{
	int received = 0;
	while (1) {
		int res = read(fd, (void *)(buf + received), buflen - received);
		if (res < 0) {
			VWIFI_ERROR(res);
			return -1;
		}
		received += res;
		if (received == buflen) {
			break;
		}
	}
	return 0;
}

static inline int _send_message(int fd, char *buf, int buflen)
{
	int sent = 0;
	while (1) {
		int res = write(fd, (void *)(buf + sent), buflen - sent);
		if (res < 0) {
			VWIFI_ERROR(res);
			return -1;
		}
		sent += res;
		if (sent == buflen) {
			break;
		}
	}
	return 0;
}


static inline int _progress_message(struct vwifi_req *req)
{
	int fd = open(VWIFI_MSG_QUEUE_NAME, O_WRONLY);
	if (fd < 0) {
		VWIFI_ERROR(0);
		return -1;
	}

	struct vwifi_msg *msg = NULL;
	int res = _create_message(&msg, req);
	if (res < 0) {
		VWIFI_ERROR(res);
		close(fd);
		return -1;
	}

	res = _send_message(fd, (char *)msg, sizeof(struct vwifi_msg));
	close(fd);
	if (res < 0) {
		VWIFI_ERROR(res);
		_destroy_message(msg);
		return -1;
	}

	_wait_message(msg);
	_destroy_message(msg);

	return 0;
}


int _vwifi_create_msgqueue(int *fd)
{
	int res = mkfifo(VWIFI_MSG_QUEUE_NAME, 0666);
	if (res < 0 && res != -EEXIST) {
		VWIFI_ERROR(0);
		return -1;
	}

	*fd = open(VWIFI_MSG_QUEUE_NAME, O_RDWR);
	if (*fd < 0) {
		VWIFI_ERROR(0);
		unlink(VWIFI_MSG_QUEUE_NAME);
		return -1;
	}

	return 0;
}

/*
 * Interface API
 */
trwifi_result_e vdev_init(struct netdev *dev)
{
	VWIFI_ENTRY;

	struct vwifi_req req = {VWIFI_MSG_INIT, NULL, 0};
	int res = _progress_message(&req);
	if (res < 0) {
		VWIFI_ERROR(0);
		return TRWIFI_FAIL;
	}
	return req.res;
}

trwifi_result_e vdev_deinit(struct netdev *dev)
{
	VWIFI_ENTRY;

	struct vwifi_req req = {VWIFI_MSG_DEINIT, NULL, 0};
	int res = _progress_message(&req);
	if (res < 0) {
		return TRWIFI_FAIL;
	}
	return TRWIFI_SUCCESS;
}

trwifi_result_e vdev_scan_ap(struct netdev *dev, trwifi_ap_config_s *config)
{
	VWIFI_ENTRY;

	struct vwifi_req req = {VWIFI_MSG_SCANAP, NULL, 0};
	int res = _progress_message(&req);
	if (res < 0) {
		return TRWIFI_FAIL;
	}
	return TRWIFI_SUCCESS;
}

trwifi_result_e vdev_connect_ap(struct netdev *dev, trwifi_ap_config_s *ap_connect_config, void *arg)
{
	VWIFI_ENTRY;

	struct vwifi_req req = {VWIFI_MSG_CONNECTAP, NULL, 0};
	int res = _progress_message(&req);
	if (res < 0) {
		return TRWIFI_FAIL;
	}
	return TRWIFI_SUCCESS;
}

trwifi_result_e vdev_disconnect_ap(struct netdev *dev, void *arg)
{
	VWIFI_ENTRY;

	struct vwifi_req req = {VWIFI_MSG_DISCONENCTAP, NULL, 0};
	int res = _progress_message(&req);
	if (res < 0) {
		return TRWIFI_FAIL;
	}
	return TRWIFI_SUCCESS;
}

trwifi_result_e vdev_get_info(struct netdev *dev, trwifi_info *wifi_info)
{
	VWIFI_ENTRY;

	unsigned char vwifi_mac[6] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
	wifi_info->ip4_address = 0x01020304;
	memcpy(wifi_info->mac_address, vwifi_mac, 6);
	wifi_info->rssi = 30;
	wifi_info->wifi_status = TRWIFI_DISCONNECTED;

	return TRWIFI_SUCCESS;
}

trwifi_result_e vdev_start_softap(struct netdev *dev, trwifi_softap_config_s *softap_config)
{
	VWIFI_ENTRY;

	struct vwifi_req req = {VWIFI_MSG_STARTSOFTAP, NULL, 0};
	uint8_t *ssid = (uint8_t *)kmm_zalloc(softap_config->ssid_length + 1);
	if (!ssid) {
		return TRWIFI_FAIL;
	}
	strncpy((char *)ssid, softap_config->ssid, softap_config->ssid_length);
	req.arg = ssid;
	int res = _progress_message(&req);
	if (res < 0) {
		return TRWIFI_FAIL;
	}
	return TRWIFI_SUCCESS;
}

trwifi_result_e vdev_start_sta(struct netdev *dev)
{
	VWIFI_ENTRY;

	struct vwifi_req req = {VWIFI_MSG_STARTSTA, NULL, 0};
	int res = _progress_message(&req);
	if (res < 0) {
		return TRWIFI_FAIL;
	}
	return TRWIFI_SUCCESS;
}

trwifi_result_e vdev_stop_softap(struct netdev *dev)
{
	VWIFI_ENTRY;

	struct vwifi_req req = {VWIFI_MSG_STOPSOFTAP, NULL, 0};
	int res = _progress_message(&req);
	if (res < 0) {
		return TRWIFI_FAIL;
	}

	return TRWIFI_SUCCESS;
}

trwifi_result_e vdev_set_autoconnect(struct netdev *dev, uint8_t check)
{
	VWIFI_ENTRY;

	struct vwifi_req req = {VWIFI_MSG_SETAUTOCONNECT, NULL, 0};
	int res = _progress_message(&req);
	if (res < 0) {
		return TRWIFI_FAIL;
	}

	return TRWIFI_SUCCESS;
}

int vdev_linkoutput(struct netdev *dev, void *buf, uint16_t dlen)
{
	VWIFI_ENTRY;
	vwifi_handle_packet(buf, dlen);
	return TRWIFI_SUCCESS;
}

int vdev_set_multicast_list(struct netdev *dev, const struct in_addr *group, netdev_mac_filter_action action)
{
	VWIFI_ENTRY;
	return TRWIFI_SUCCESS;
}

/*
 * Internal Function
 */
struct netdev* vdev_register_dev(int sizeof_priv)
{
	struct nic_io_ops nops = {vdev_linkoutput, vdev_set_multicast_list};
	struct netdev_config nconfig;
	nconfig.ops = &nops;
	nconfig.flag = NM_FLAG_ETHARP | NM_FLAG_ETHERNET | NM_FLAG_BROADCAST | NM_FLAG_IGMP;
	nconfig.mtu = CONFIG_NET_ETH_MTU; // is it right that vendor decides MTU size??
	nconfig.hwaddr_len = IFHWADDRLEN;
	nconfig.is_default = 1;

	nconfig.type = NM_WIFI;
	nconfig.t_ops.wl = &g_trwifi_drv_ops;
	nconfig.priv = NULL;

	return netdev_register(&nconfig);
}


void vdev_run(int argc, char *argv[])
{
	g_vwifi_dev = vdev_register_dev(0);
	if (!g_vwifi_dev) {
		VWIFI_ERROR(0);
		return;
	}
	netdev_set_hwaddr(g_vwifi_dev, g_hwaddr, IFHWADDRLEN);

	int fd;
	int res = _vwifi_create_msgqueue(&fd);
	if (res < 0) {
		VWIFI_ERROR(0);
		return;
	}

	fd_set rfds, tfds;
	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);

	while (1) {
		tfds = rfds;
		res = select(fd + 1, &tfds, NULL, NULL, NULL);
		if (res <= 0) {
			VWIFI_ERROR(res);
			if (errno == EINTR) {
				continue;
			}
			break;
		}
		struct vwifi_msg msg;
		res = _recv_message(fd, (char *)&msg, sizeof(struct vwifi_msg));
		if (res < 0) {
			VWIFI_ERROR(res);
			break;
		}
		res = vwifi_handle_message(msg.req);

		if (res < 0) {
			VWIFI_ERROR(res);
			break;
		}
		_send_signal(&msg);
	}
	return;
}

void vwifi_send_packet(uint8_t *buf, uint32_t len)
{
	if (!g_vwifi_dev) {
		VWIFI_ERROR(0);
		return;
	}
	netdev_input(g_vwifi_dev, buf, len);
}

void vwifi_start(void)
{
	vwifi_initialize_scan();
	int new_thread = kernel_thread("virtual wifi", 100, 2048, (main_t)vdev_run, (char *const *)NULL);
	if (new_thread < 0) {
		VWIFI_ERROR(new_thread);
	}
	return;
}

void up_netinitialize(void)
{
	return;
}

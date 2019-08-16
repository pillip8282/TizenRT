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

#ifndef __TIZENRT_NETMGR_H__
#define __TIZENRT_NETMGR_H__

/****************************************************************************
 * Included Files
 ****************************************************************************/
#include <tinyara/config.h>


typedef enum {
	NM_WIFI,
	NM_ETHERNET,
} netdev_type;

/*  lwip dependent: need to change it to independent to lwip */
/*  ToDo : remove lwip structures */
struct nic_io_ops {
	int (*linkoutput)(struct netif *netif, struct pbuf *buf);
	int (*input)(pbuf *buf, int buf_len);
	int (*output)(struct netif *netif, struct pbuf *q, const ip4_addr_t *ipaddr);
	int (*output_ipv6)(struct netif * netif, struct pbuf * p, const ip6_addr_t * ipaddr);
	int (*igmp_mac_filter)(struct netif * netif, const ip4_addr_t * group, enum netif_mac_filter_action action);
};

struct netdev_config {
	struct nic_io_ops ops;
	int flag;
	int mtu;
	int hwaddr_len;
	/*	Device address */
	struct sockaddr addr; // ipv6, ipv4
	struct sockaddr netmask;
	struct sockaddr gw;
	struct sockaddr_storage addr6; // ipv6, ipv4
	struct sockaddr_storage netmask6;
	struct sockaddr_storage gw6;

	int is_default;
	union {
		struct ethernet_ops eth;
		struct lwnl80211_ops wl;
	} t_ops;
	netdev_type type;

	int (*d_ioctl)(struct netdev *dev, int cmd, unsigned long arg);
	void *priv;
};

/**
 * Public API
 */
/*
 * desc: register a network device
 * return: return netif registered
 */
struct netdev *register_netdev(struct netdev_config *config);

#endif // __TIZENRT_NETMGR_H__

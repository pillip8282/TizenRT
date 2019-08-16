#ifndef __TIZENRT_NETDEV_MGR_INTERNAL_H__
#define __TIZENRT_NETDEV_MGR_INTERNAL_H__

#include <tinyara/net/netdev_mgr.h>

#include <tinyara/lwnl/lwnl80211.h>
#include <tinyara/net/ethernet.h>
#ifdef CONFIG_NET_LWIP
#include <net/lwip/netif.h>
#endif

struct nic_config {
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
	struct nic_io_ops io_ops;
};

struct netdev {
	char ifname[IFNAMSIZ];

	/*	data plane */
	struct netdev_ops *ops;

	/*  device control to proceed mii */
	int (*d_ioctl)(struct netdev *dev, int cmd, unsigned long arg);

	netif_type type;
	union {
		struct ethernet_ops eth;
		struct lwnl80211_ops wl;
	} t_ops;

	void *priv;
};

struct netdev_ops {
	int (*get_ip4addr)(struct netdev *dev, struct sockaddr *addr, int type);
	int (*set_ip4addr)(struct netdev *dev, struct sockaddr *addr, int type);
	int (*get_ip6addr)(struct netdev *dev, struct sockaddr_storage *addr, int type);
	int (*set_ip6addr)(struct netdev *dev, struct sockaddr_storage *addr, int type);
	int (*delete_ipaddr)(struct netdev *dev);

	int (*get_hwaddr)(struct netdev *dev, sockaddr *hwaddr);
	int (*set_hwaddr)(struct netdev *dev, sockaddr *hwaddr);

	int (*get_mtu)(struct netdev *dev, int *mtu);
	int (*get_flag)(struct netdev *dev, int *flag);

	int (*ifup)(struct netdev *dev);
	int (*ifdown)(struct netdev *dev);

	/* multicast
	 */
	int (*joingroup)(struct netdev *dev, struct in_addr *addr);
	int (*leavegroup)(struct netdev *dev, struct in_addr *addr);
};

struct netdev *get_netdev(char *ifname);
int netdev_count(void);

#endif // __TIZENRT_NETDEV_MGR_INTERNAL_H__

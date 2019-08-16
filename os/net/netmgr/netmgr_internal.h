#ifndef _NETMGR_INTERNAL_H__
#define _NETMGR_INTERNAL_H__

#include <tinyara/config.h>


#ifndef CONFIG_NET_NUM_NETDEV
#define NUM_NETDEV 3
#else
#define NUM_NETDEV CONFIG_NET_NUM_NETDEV
#endif


struct netmgr {
	struct netdev dev_list[NUM_NETDEV];
	struct netstack *stk;
};

/**
 * General
 */
/*
 * desc: return the number of registered devices
 */
int netmgr_count(void);

/*
 * desc: get the information of registered devices
 */
int netmgr_getinfo(void *req);

/*
 * desc: get a matching netdev
 */
int netmgr_getnetdev(char *ifname);

/**
 * routing
 */
int netmgr_addroute(struct rtentry *entry);

int netmgr_delroute(struct rtentry *entry);

#endif // _NETMGR_INTERNAL_H__

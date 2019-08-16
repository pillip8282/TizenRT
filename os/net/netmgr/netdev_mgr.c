#include <tinyara/config.h>
#include <tinyara/net/netdev_mgr.h>
#include <netdev_mgr_internal.h>
#include <debug.h>
#include <semaphore.h>

#ifndef CONFIG_NETDEV_NUM
#define CONFIG_NETDEV_NUM 3
#endif

#define NETDEV_MGR_WIFI_NAME "wl"
#define NETDEV_MGR_ETHERNET_NAME "eth"

static struct netdev g_netdevices[CONFIG_NETDEV_NUM];
static int g_netdev_idx = 0;
static int g_wlan_idx = 0;
static int g_eth_idx = 0;

/* protect access of g_netdevices and g_netdev_idx
 * netdev is set while system is resetting.
 * and application doesn't require write operation to netdev
 * so if there is no write operation then protection wouldn't be required
 */
sem_t g_netdev_lock = SEM_INITIALIZER(1);

#define NETDEV_LOCK								\
	do {										\
		sem_wait(&g_netdev_lock);				\
	} while (0)

#define NETDEV_UNLOCK							\
	do {										\
		sem_post(&g_netdev_lock);				\
	} while (0)

/*
 * external function
 */
#ifdef CONFIG_NET_LWIP
// the way to get lwip stack need to be changed.
extern struct netdev_ops *get_netdev_ops_lwip(void);
#endif

struct netdev *get_netdev(char *ifname)
{
	for (int i = 0; i < g_netdev_idx; i++) {
		if (!strcmp(ifname, g_netdevices[i].ifname)) {
			return &g_netdevices[i];
		}
	}
	return NULL;
}

int netdev_count(void)
{
	return g_netdev_idx;
}

struct netdev *register_netdev(struct netdev_config *config)
{
	//NETDEV_LOCK;
	if (g_netdev_idx == CONFIG_NETDEV_NUM) {
		return NULL;
	}

	struct netdev *dev = &g_netdevcies[g_netdev_idx++];

	char name[IFNAMSIZ] = {0,}
	if (config->type == NM_WIFI) {
		snprintf(name, IFNAMSIZ, "%s%d", NETDEV_MGR_WIFI_NAME, g_wlan_idx++);
		strncpy(dev->ifname, name, IFNAMSIZ);
		dev->t_ops.wl = config->t_ops.wl;
	} else if (config->type == NM_WIFI) {
		snprintf(name, IFNAMSIZ, "%s%d", NETDEV_MGR_ETHERNET_NAME, g_eth_idx++);
		strncpy(dev->ifname, name, IFNAMSIZ);
		dev->t_ops.eth = config->t_ops.eth;
	} else {
		ndbg("unknown type\n");
		return NULL;
	}
	dev->d_ioctl = config->d_ioctl;

	struct nic_config nconfig;
	nconfig->flag = config->flag;
	nconfig->mtu = config->mtu;
	nconfig->hwaddr = config->hwaddr_len;
	nconfig->addr = config->addr;
	nconfig->netmask = config->netmask;
	nconfig->addr6 = config->addr6;
	nconfig->netmask6 = config->netmask6;
	nconfig->gw6 = config->gw6;
	nconfig->is_default = config->is_default;
#ifdef CONFIG_NET_LWIP
	dev->nic = get_nic_lwip(&nconfig);
	dev->ops = get_netdev_ops_lwip();
#endif

	dev->priv = config->priv;

	//NETDEV_UNLOCK;
}

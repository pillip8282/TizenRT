#include <tinyara/config.h>
#include "netdev_mgr_internal.h"

static FAR struct net_driver_s *_netdev_ifrdev(FAR struct ifreq *req)
{
	if (req != NULL) {
		return get_netdev(req->ifr_name);
	}
	return NULL;
}

/****************************************************************************
 * Name: netdev_ifrioctl
 *
 * Description:
 *   Perform network device specific operations.
 *
 * Parameters:
 *   psock    Socket structure
 *   dev      Ethernet driver device structure
 *   cmd      The ioctl command
 *   req      The argument of the ioctl cmd
 *
 * Return:
 *   >=0 on success (positive non-zero values are cmd-specific)
 *   Negated errno returned on failure.
 *
 ****************************************************************************/

int netdev_ifrioctl(FAR struct socket *sock, int cmd, FAR struct ifreq *req)
{
	FAR struct netdev *dev;
	int ret = -EINVAL;
	(void)sock;

	nvdbg("cmd: %d\n", cmd);

	/* Execute the command */
	switch (cmd) {

	case SIOCGIFADDR: {			/* Get IP address */
		dev = _netdev_ifrdev(req);
		if (!dev) {
			break;
		}
		ret = dev->ops->get_ip4addr(dev, &req->ifr_addr, NETDEV_IP);
	}
		break;
	case SIOCSIFADDR: {			/* Set IP address */
		dev = _netdev_ifrdev(req);
		if (!dev) {
			break;
		}
		ret = dev->ops->set_ip4addr(dev, &req->ifr_addr, NETDEV_IP);
	}
		break;

	case SIOCGIFDSTADDR: {		/* Get P-to-P address */
		dev = _netdev_ifrdev(req);
		if (!dev) {
			break;
		}
		ret = dev->ops->get_ip4addr(dev, &req->ifr_addr, NETDEV_GW);
	}
		break;

	case SIOCSIFDSTADDR: {		/* Set P-to-P address */
		dev = _netdev_ifrdev(req);
		if (!dev) {
			break;
		}
		ret = dev->ops->set_ip4addr(dev, &req->ifr_addr, NETDEV_GW);
	}
		break;

	case SIOCGIFBRDADDR:		/* Get broadcast IP address */
	case SIOCSIFBRDADDR: {		/* Set broadcast IP address */
		ret = -ENOSYS;
	}
		break;

	case SIOCGIFNETMASK: {		/* Get network mask */
		dev = _netdev_ifrdev(req);
		if (!dev) {
			break;
		}
		ret = dev->ops->get_ip4addr(dev, &req->ifr_addr, NETDEV_NETMASK);
	}
		break;

	case SIOCSIFNETMASK: {		/* Set network mask */
		dev = _netdev_ifrdev(req);
		if (!dev) {
			break;
		}
		ret = dev->ops->set_ip4addr(dev, &req->ifr_addr, NETDEV_NETMASK);
	}
		break;

		/* TODO: Support IPv6 related IOCTL calls once IPv6 is functional */
	case SIOCGLIFADDR: {		/* Get IP address */
		dev = _netdev_ifrdev(req);
		if (!dev) {
			break;
		}
		ret = dev->ops->get_ip6addr(dev, &(((struct lifreq *)req)->lifr_addr), NETDEV_IP);
	}
		break;

	case SIOCSLIFADDR: {		/* Set IP address */
		dev = _netdev_ifrdev(req);
		if (!dev) {
			break;
		}
		ret = dev->ops->set_ip6addr(dev, &(((struct lifreq *)req)->lifr_addr), NETDEV_IP);
	}
		break;

	case SIOCGLIFDSTADDR: {		/* Get P-to-P address */
		dev = _netdev_ifrdev(req);
		if (!dev) {
			break;
		}
		ret = dev->ops->get_ip6addr(dev, &(((struct lifreq *)req)->lifr_addr), NETDEV_GW);
	}
		break;

	case SIOCSLIFDSTADDR: {		/* Set P-to-P address */
		dev = _netdev_ifrdev(req);
		if (!dev) {
			break;
		}
		ret = dev->ops->set_ip6addr(dev, &(((struct lifreq *)req)->lifr_addr), NETDEV_GW);
	}
		break;

	case SIOCGLIFBRDADDR:		/* Get broadcast IP address */
	case SIOCSLIFBRDADDR: {		/* Set broadcast IP address */
		ret = -ENOSYS;
	}
		break;

	case SIOCGLIFNETMASK: {		/* Get network mask */
		dev = _netdev_ifrdev(req);
		if (!dev) {
			break;
		}
		ret = dev->ops->get_ip6addr(dev, &(((struct lifreq *)req)->lifr_addr), NETDEV_IP);
	}
		break;

	case SIOCSLIFNETMASK: {		/* Set network mask */
		dev = _netdev_ifrdev(req);
		if (!dev) {
			break;
		}
		ret = dev->ops->set_ip6addr(dev, &(((struct lifreq *)req)->lifr_addr), NETDEV_NETMASK);
	}
		break;
	case SIOCGLIFMTU:			/* Get MTU size */
	case SIOCGIFMTU: {			/* Get MTU size */
		dev = _netdev_ifrdev(req);
		if (!dev) {
			break;
		}
		ret = dev->ops->get_mtu(dev, &req->ifr_mtu);
	}
		break;

	case SIOCSIFFLAGS: {		/* Sets the interface flags */
		/* Is this a request to bring the interface up? */
		dev = _netdev_ifrdev(req);
		if (!dev) {
			break;
		}
		if (req->ifr_flags & IFF_UP) {
			ret = dev->ops->ifup(dev);
		} else if (req->ifr_flags & IFF_DOWN) {
			ret = dev->ops->ifdown(dev);
		}
		ret = OK;
	}
		break;

	case SIOCGIFFLAGS: {		/* Gets the interface flags */
		dev = _netdev_ifrdev(req);
		if (!dev) {
			break;
		}
		ret = dev->ops->get_flag(dev, &req->ifr_flags);
	}
		break;

		/* MAC address operations only make sense if Ethernet is supported */
	case SIOCGIFHWADDR: {		/* Get hardware address */
		dev = _netdev_ifrdev(req);
		if (!dev) {
			break;
		}
		ret = dev->ops->get_hwaddr(dev, req->ifr_hwaddr.sa_data);
	}
		break;

	case SIOCSIFHWADDR: {		/* Set hardware address -- will not take effect until ifup */
		dev = _netdev_ifrdev(req);
		if (!dev) {
			break;
		}
		ret = dev->ops->set_hwaddr(dev, req->ifr_hwaddr.sa_data);
	}
		break;

	case SIOCDIFADDR: {			/* Delete IP address */
		dev = _netdev_ifrdev(req);
		if (!dev) {
			break;
		}
		ret = dev->ops->delete_ipaddr(dev);
	}
		break;

	case SIOCGIFCOUNT: {		/* Get number of devices */
		req->ifr_count = netmgr_count();
		ret = OK;
	}
		break;

#ifdef CONFIG_NET_ARPIOCTLS
	case SIOCSARP:				/* Set a ARP mapping */
	case SIOCDARP:				/* Delete an ARP mapping */
	case SIOCGARP:				/* Get an ARP mapping */
#error "IOCTL Commands not implemented"
#endif							/* CONFIG_NET_ARPIOCTLS */

#ifdef CONFIG_NETDEV_PHY_IOCTL
	case SIOCGMIIPHY:			/* Get address of MII PHY in use */
	case SIOCGMIIREG:			/* Get MII register via MDIO */
	case SIOCSMIIREG: {			/* Set MII register via MDIO */
		dev = _netdev_ifrdev(req);
		if (!dev || !dev->d_ioctl) {
			break;
		}
		struct mii_ioctl_data_s *mii_data = &req->ifr_ifru.ifru_mii_data;
		ret = dev->d_ioctl(dev, cmd, ((long)(uintptr_t)mii_data));
	}
		break;
#endif							/* CONFIG_NETDEV_PHY_IOCTL */
	case SIOCGIFCONF:
		ret = ioctl_siocgifconf((FAR struct ifconf *)req);
		break;
	default: {
		ret = -ENOTTY;
	}
		break;
	}

	return ret;
}

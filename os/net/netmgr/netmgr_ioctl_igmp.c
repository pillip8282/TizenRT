#include <tinyara/config.h>

#include "sys/sockio.h"

static FAR struct netdev *_netdev_imsfdev(FAR struct ip_msfilter *imsf)
{
	if (!imsf) {
		return NULL;
	}
	/* Find the network device associated with the device name
	 * in the request data.
	 */
	return netmgr_getnetdev(imsf->imsf_name);
}

/****************************************************************************
 * Name: netdev_imsfioctl
 *
 * Description:
 *   Perform network device specific operations.
 *
 * Parameters:
 *   psock    Socket structure
 *   dev      Ethernet driver device structure
 *   cmd      The ioctl command
 *   imsf     The argument of the ioctl cmd
 *
 * Return:
 *   >=0 on success (positive non-zero values are cmd-specific)
 *   Negated errno returned on failure.
 *
 ****************************************************************************/
int netdev_imsfioctl(FAR struct socket *sock, int cmd, FAR struct ip_msfilter *imsf)
{
	FAR struct netdev *dev;
	int ret = -EINVAL;

	nvdbg("cmd: %d\n", cmd);

	/* Execute the command */
	switch (cmd) {
	case SIOCSIPMSFILTER: {		/* Set source filter content */
		dev = _netdev_imsfdev(imsf);
		if (!dev) {
			break;
		}

		if (imsf->imsf_fmode == MCAST_INCLUDE) {
			ret = dev->ops->joingroup(dev, &imsf->imsf_multiaddr);
		} else {
			DEBUGASSERT(imsf->imsf_fmode == MCAST_EXCLUDE);
			ret = dev->ops->leavegroup(dev, &imsf->imsf_multiaddr);
		}
	}
	break;
	case SIOCGIPMSFILTER:		/* Retrieve source filter addresses */
	default:
		ret = -ENOTTY;
		break;
	}

	return ret;
}

#include <tinyara/config.h>

/****************************************************************************
 * Name: netdev_rtioctl
 *
 * Description:
 *   Perform routing table specific operations.
 *
 * Parameters:
 *   psock    Socket structure
 *   dev      Ethernet driver device structure
 *   cmd      The ioctl command
 *   rtentry  The argument of the ioctl cmd
 *
 * Return:
 *   >=0 on success (positive non-zero values are cmd-specific)
 *   Negated errno returned on failure.
 *
 ****************************************************************************/
static int netdev_rtioctl(FAR struct socket *sock, int cmd, FAR struct rtentry *rtentry)
{
	int ret = -EAFNOSUPPORT;

	/* Execute the command */

	switch (cmd) {
	case SIOCADDRT: {			/* Add an entry to the routing table */
		/* The target address and the netmask are required values */
		ret = netmgr_addroute(rtentry);
	}
	break;

	case SIOCDELRT: {			/* Delete an entry from the routing table */
		/* The target address and the netmask are required values */
		ret = netmgr_delroute(rtentry);
	}
	break;

	default:
		ret = -ENOTTY;
		break;
	}

	return ret;
}

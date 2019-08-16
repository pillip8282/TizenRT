#include <tinyara/config.h>

#include <errno.h>
#include <sys/ioctl.h>

/****************************************************************************
 * Function: netdev_getstats
 *
 * Description:
 *   Return the specific interface stats
 *
 * Parameters:
 *   arg Type of information to get
 *
 * Returned Value:
 *   0:Success; negated errno on failure
 *
 ****************************************************************************/
static int netdev_getstats(void *arg)
{
	int ret = -EINVAL;
	struct netif *dev;
	struct netmon_netdev_stats *stats = (struct netmon_netdev_stats *)arg;
	if (stats) {
		char *intf = stats->devname;
		dev = netdev_findbyname(intf);
		if (dev) {
			netdev_semtake();
			stats->devinpkts = dev->mib2_counters.ifinucastpkts +
				dev->mib2_counters.ifinnucastpkts +
				dev->mib2_counters.ifindiscards +
				dev->mib2_counters.ifinerrors +
				dev->mib2_counters.ifinunknownprotos;

			stats->devinoctets = dev->mib2_counters.ifinoctets;
			stats->devoutpkts = dev->mib2_counters.ifoutucastpkts +
				dev->mib2_counters.ifoutnucastpkts +
				dev->mib2_counters.ifoutdiscards +
				dev->mib2_counters.ifouterrors;

			stats->devoutoctets = dev->mib2_counters.ifoutoctets;
			netdev_semgive();
			ret = OK;
		}
	}
	return ret;
}


/****************************************************************************
 * Name: netdev_nmioctl
 *
 * Description:
 *   Perform network monitor specific operations.
 *
 * Parameters:
 *   sock    Socket structure
 *   cmd     The ioctl command
 *   arg    The argument of ioctl command
 *
 * Return:
 *   >=0 on success (positive non-zero values are cmd-specific)
 *   Negated errno returned on failure.
 *
 ****************************************************************************/
int netdev_nmioctl(FAR struct socket *sock, int cmd, void  *arg)
{
	int ret = -EINVAL;
	int num_copy;
	switch (cmd) {
	case SIOCGETSOCK:          /* Get socket info. */
		num_copy = copy_socket(arg);
		/* num_copy shoud be larger than 0 (this socket) */
		if (num_copy > 0) {
			ret = OK;
		} else {
			ret = -EINVAL;
		}
		break;
#ifdef CONFIG_NET_STATS
	case SIOCGDSTATS:          /* Get netdev info. */
		ret = netdev_getstats(arg);
		break;
#endif
	default:
		ret = -ENOTTY;
		break;
	} /* end switch */

	return ret;
}

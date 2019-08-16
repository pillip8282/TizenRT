#include <tinyara/config.h>
#include <tinyara/net/netmgr.h>

/****************************************************************************
 * Name: netmgr_setup
 *
 * Description:
 *   This is called from the OS initialization logic at power-up reset in
 *   order to configure networking data structures.  This is called prior
 *   to platform-specific driver initialization so that the networking
 *   subsystem is prepared to deal with network driver initialization
 *   actions.
 *
 *   Actions performed in this initialization phase assume that base OS
 *   facilities such as semaphores are available but this logic cannot
 *   depend upon OS resources such as interrupts or timers which are not
 *   yet available.
 *
 * Input Parameters:
 *   None
 *
 * Returned Value:
 *   None
 *
 ****************************************************************************/

void netmgr_setup(void)
{
	/* Initialize the locking facility */

	net_lockinitialize();

#ifdef CONFIG_NET_ROUTE
	/* Initialize the routing table */

	net_initroute();
#endif

#if CONFIG_NSOCKET_DESCRIPTORS > 0
	/* Initialize the socket layer */

	netdev_seminit();
#endif
	struct netmgr_stack_ops *s_ops = get_netstack();
	int res = s_ops->init(NULL);
	
}

/****************************************************************************
 * Name: netmgr_start
 *
 * Description:
 *   This function is called from the OS initialization logic at power-up
 *   reset AFTER initialization of hardware facilities such as timers and
 *   interrupts.   This logic completes the initialization started by
 *   net_setup().
 *
 * Input Parameters:
 *   None
 *
 * Returned Value:
 *   None
 *
 ****************************************************************************/

void netmgr_start(void)
{
	struct netmgr_stack_ops *s_ops = get_netstack();
	int res = s_ops->start(NULL);
	
	return;
}

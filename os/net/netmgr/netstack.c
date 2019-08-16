#include <tinyara/config.h>
#include "netstack.h"

#ifdef CONFIG_NET_LWIP
extern struct netstack *get_netstack_lwip(void);
#endif

struct netstack *get_netstack(void)
{
#ifdef CONFIG_NET_LWIP
	return get_netstack_lwip();
#else
	return NULL;
#endif
}

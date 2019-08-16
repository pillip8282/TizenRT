
extern struct netmgr_stack_ops *get_lwip_netstack(void);

struct netmgr_stack_ops *get_netstack(void)
{
	return get_lwip_netstack();
}

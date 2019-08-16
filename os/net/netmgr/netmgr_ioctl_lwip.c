#include <tinyara/config.h>

/****************************************************************************
 * Function: lwip_func_ioctl
 *
 * Description:
 *   Call lwip API
 *
 * Parameters:
 *   cmd      The ioctl command
 *   arg      Type of the information to get
 *
 * Returned Value:
 *   0 on success, negated errno on failure.
 *
 ****************************************************************************/
static int lwip_func_ioctl(int cmd, void *arg)
{
	int ret = -EINVAL;
	struct req_lwip_data *in_arg = (struct req_lwip_data *)arg;
	if (!in_arg) {
		return ret;
	}

	struct addrinfo *res = NULL;
	struct hostent *host_ent = NULL;
	struct hostent *user_ent = NULL;

	switch (in_arg->type) {
#if LWIP_DNS
	case GETADDRINFO:
		in_arg->req_res = lwip_getaddrinfo(in_arg->host_name, in_arg->serv_name, in_arg->ai_hint, &res);
		if (in_arg->req_res != 0) {
			ndbg("lwip_getaddrinfo() returned with the error code: %d\n", ret);
			in_arg->ai_res = NULL;
			ret = -EINVAL;
		} else {
			in_arg->ai_res = copy_addrinfo(res);
			ret = OK;
		}
		break;
	case FREEADDRINFO:
		in_arg->req_res = free_addrinfo(in_arg->ai);
		ret = OK;
		break;
	case DNSSETSERVER:
		dns_setserver(in_arg->num_dns, in_arg->dns_server);
		ret = OK;
		break;
	case GETHOSTBYNAME:
		host_ent = lwip_gethostbyname(in_arg->host_name);
		if (!host_ent) {
			ndbg("lwip_gethostbyname() returned with the error code: %d\n", HOST_NOT_FOUND);
			ret = -EINVAL;
		} else {
			user_ent = in_arg->host_entry;
			strncpy(user_ent->h_name, host_ent->h_name, DNS_MAX_NAME_LENGTH);
			user_ent->h_name[DNS_MAX_NAME_LENGTH] = 0;
			memcpy(user_ent->h_addr_list[0], host_ent->h_addr_list[0], sizeof(struct in_addr));
			user_ent->h_addrtype = host_ent->h_addrtype;
			user_ent->h_length = host_ent->h_length;

			ret	= OK;
		}
		break;
	case GETNAMEINFO:
		in_arg->req_res = lwip_getnameinfo(in_arg->sa, in_arg->sa_len, (char *)in_arg->host_name, in_arg->host_len, (char *)in_arg->serv_name, in_arg->serv_len, in_arg->flags);
		if (in_arg->req_res != 0) {
			ndbg("lwip_getnameinfo() returned with the error code: %d\n", ret);
			ret = -EINVAL;
		} else {
			ret = OK;
		}
		break;
#endif

#if defined(CONFIG_NET_LWIP_DHCP)
#if defined(CONFIG_LWIP_DHCPC)
	case DHCPCSTART:
		in_arg->req_res = netdev_dhcp_client_start((const char *)in_arg->host_name);
		if (in_arg->req_res != 0) {
			ret = -EINVAL;
			ndbg("start dhcp fail\n");
		} else {
			ret = OK;
		}
		break;
	case DHCPCSTOP:
		netdev_dhcp_client_stop((const char *)in_arg->host_name);
		in_arg->req_res = 0;
		ret = OK;
		break;
#endif

#if defined(CONFIG_LWIP_DHCPS)
	case DHCPDSTART:
		in_arg->req_res = netdev_dhcp_server_start((char *)in_arg->host_name, _dhcpd_join);
		if (in_arg->req_res != 0) {
			ret = -EINVAL;
			ndbg("start dhcpd fail\n");
		} else {
			ret = OK;
		}
		break;
	case DHCPDSTOP:
		in_arg->req_res = netdev_dhcp_server_stop((char *)in_arg->host_name);
		if (in_arg->req_res != 0) {
			ret = -EINVAL;
			ndbg("stop dhcpd fail\n");
		} else {
			ret = OK;
		}
		break;
	case DHCPDSTATUS:
		in_arg->req_res = netdev_dhcp_server_status((char *)in_arg->host_name);
		if (in_arg->req_res != 0) {
			ret = -EINVAL;
			ndbg("stop dhcpd fail\n");
		} else {
			ret = OK;
		}
		break;
#endif // CONFIG_LWIP_DHCPS
#endif // CONFIG_NET_LWIP_DHCP
	default:
		ndbg("Wrong request type: %d\n", in_arg->type);
		break;
	}

	return ret;
}

/****************************************************************************
 * Function: lwipioctl
 *
 * Description:
 *   Call lwip_ioctl() with FIONREAD/FIONBIO commands or
 *   call lwip API with SIOCLWIP command
 *
 * Parameters:
 *   sockfd   Socket file descriptor
 *   cmd      The ioctl command
 *   arg      Type of the information to get
 *
 * Returned Value:
 *   0 on success, negated errno on failure.
 *
 ****************************************************************************/

int netdev_lwipioctl(int sockfd, int cmd, void *arg)
{
	int ret = -ENOTTY;

	if (cmd == FIONREAD || cmd == FIONBIO) {
		ret = lwip_ioctl(sockfd, (long)cmd, arg);
		if (ret == -1) {
			return -get_errno();
		}
	} else if (cmd == SIOCLWIP) {
		return lwip_func_ioctl(cmd, arg);
	}

	return ret;
}

#ifndef _LWIP_IOCTL_H__
#define _LWIP_IOCTL_H__

#ifdef CONFIG_NET_LWIP
#include <stdint.h>
#include <sys/types.h>
#include <net/lwip/ip_addr.h>

// ToDo make it stack specific ioctl
// so it has independent to the stack

typedef enum {
	GETADDRINFO,
	FREEADDRINFO,
	GETHOSTBYNAME,
	GETNAMEINFO,
	DNSSETSERVER,
	DHCPCSTART,
	DHCPCSTOP,
	DHCPDSTART,
	DHCPDSTOP,
	DHCPDSTATUS,
} req_type;

/* To send a request to lwip stack by ioctl() use */
struct req_lwip_data {
	req_type type;
	int req_res;
	const char *host_name;
	const char *serv_name;
	const struct addrinfo *ai_hint;
	struct addrinfo *ai_res;
	struct addrinfo *ai;
	struct hostent *host_entry;
	const struct sockaddr *sa;
	size_t sa_len;
	size_t host_len;
	size_t serv_len;
	int flags;
	uint8_t num_dns;
	ip_addr_t *dns_server;
};

#endif //  CONFIG_NET_LWIP

#endif //  _LWIP_IOCTL_H__

/****************************************************************************
 *
 * Copyright 2019 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/
#include <tinyara/config.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <tinyara/netmgr/stack_ioctl.h>

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: netlib_set_dns
 *
 * Description:
 *   Get the network driver IPv6 address
 *
 * Parameters:
 *   ifname   The name of the interface to use
 *   ipaddr   The location to return the IP address
 *
 * Return:
 *   0 on success; -1 on failure
 *
 ****************************************************************************/

int netlib_set_ipv4_dns(FAR struct in_addr *addr)
{
	int ret = ERROR;
	struct req_lwip_data req;
	ip_addr_t laddr;
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		printf("dnsclient : socket() failed with errno: %d\n", errno);
		return -1;
	}
	memset(&req, 0, sizeof(req));
	req.type = DNSSETSERVER;
	req.num_dns = 0;
	ip4_addr_get_u32(ip_2_ip4(&laddr)) = addr->s_addr;
	req.dns_server = &laddr;

	ret = ioctl(sockfd, SIOCLWIP, (unsigned long)&req);
	if (ret == ERROR) {
		printf("dnsclient : ioctl() failed with errno: %d\n", errno);
		close(sockfd);
		return -1;
	}

	close(sockfd);

	return ret;
}

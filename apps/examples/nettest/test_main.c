/****************************************************************************
 *
 * Copyright 2021 Samsung Electronics All Rights Reserved.
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
#include <lwip/sockets.h>
#include <netdb.h>
#include <tinyara/config.h>
#include <stress_tool/st_perf.h>

#define NT_TEST_TRIAL 2
#define NT_MAXHOST 1024 /* refer NI_MAXHOST */
#define NT_MAXSERV 64	/* refer tmpserv in lwip_getnameinfo */
#define TC_HOST_NAME "www.google.com"
#define TC_SERVICE "80"
#define NT_STR_DNS_ADDR "8.8.8.8"

static char g_hostname[NT_MAXHOST]; // stack overflow can be happened if set this value local variable.
static char g_serv[NT_MAXSERV];
static char *g_host_list[] = {
	"www.google.com",
	"www.facebook.com",
	"www.naver.com",
	"www.daum.net",
};

static void _print_result(char *hostname, struct addrinfo *local_res)
{
	struct addrinfo *ainfo = NULL;
	printf("Host: %s\n", hostname);
	for (ainfo = local_res; ainfo != NULL; ainfo = ainfo->ai_next) {
		printf("family %s\n", ((ainfo->ai_family == AF_INET) ? "AF_INET" : "Not IPv4"));
		if (ainfo->ai_family != AF_INET) {
			printf("not interesting type %d\n", ainfo->ai_family);
			continue;
		}
		struct sockaddr_in *dst = (struct sockaddr_in *)ainfo->ai_addr;
		struct in_addr info_addr = dst->sin_addr;
		uint8_t addr[4] = {
			0,
		};
		addr[0] = info_addr.s_addr & 0xFF;
		addr[1] = (info_addr.s_addr >> 8) & 0xFF;
		addr[2] = (info_addr.s_addr >> 16) & 0xFF;
		addr[3] = (info_addr.s_addr >> 24) & 0xFF;
		printf("%d.%d.%d.%d\n", addr[0], addr[1], addr[2], addr[3]);
	}
	printf("\n");
}

static void _print_addrinfo(struct addrinfo *addr)
{
	struct addrinfo *rp;
	char buf[64];
	printf("=====================================\n");
	printf("family\tsocket type\tprotocol\taddress\n");
	printf("-------------------------------------\n");
	for (rp = addr; rp != NULL; rp = rp->ai_next) {
		printf("%d\t%d\t%d\t", rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (rp->ai_family == AF_INET) {
			inet_ntop(rp->ai_family, &(((struct sockaddr_in *)(rp->ai_addr))->sin_addr), buf, sizeof(buf));
			printf("%s\n", buf);
		} else if (rp->ai_family == AF_INET6) {
			inet_ntop(rp->ai_family, &(((struct sockaddr_in6 *)(rp->ai_addr))->sin6_addr), buf, sizeof(buf));
			printf("%s\n", buf);
		} else {
			printf("\n");
		}
	}
	printf("=====================================\n\n");
}

static void _print_serv_info(const char *host, const char *service)
{
	printf("=====================================\n");
	printf("host\tservice\n");
	printf("-------------------------------------\n");
	printf("%s\t%s\n", host, service);
	printf("=====================================\n\n");
}

static void _print_host(const struct hostent *he)
{
	struct in_addr **addr_list;
	printf("=====================================\n");
	printf("Official name is: %s\n", he->h_name);
	printf("IP address: %s\n", inet_ntoa(*(struct in_addr *)he->h_addr));
	printf("All addresses: ");
	addr_list = (struct in_addr **)he->h_addr_list;
	for (int i = 0; addr_list[i] != NULL; i++) {
		printf("%s ", inet_ntoa(*addr_list[i]));
	}
	printf("\n=====================================\n\n");
}

/*
 * Description: get socket information
 */
START_TEST_F(getaddrinfo_p)
{
	struct addrinfo hints;
	struct addrinfo *servinfo;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	int res = getaddrinfo(TC_HOST_NAME, TC_SERVICE, &hints, &servinfo);
	ST_EXPECT_EQ(0, res);
	if (res == 0) {
		_print_addrinfo(servinfo);
		freeaddrinfo(servinfo);
	}
}
END_TEST_F

/*
 * Description: verify getaddrinfo negative case
 */
START_TEST_F(getaddrinfo_n)
{
	ST_EXPECT_NEQ(0, getaddrinfo(NULL, NULL, NULL, NULL));
}
END_TEST_F

/*
 * description: getnameinfo positive
 */
START_TEST_F(getnameinfo_p)
{
	struct addrinfo hints;
	struct addrinfo *servinfo;
	int res = 0;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	res = getaddrinfo(TC_HOST_NAME, TC_SERVICE, &hints, &servinfo);
	ST_EXPECT_EQ(0, res);

	res = getnameinfo(servinfo->ai_addr, sizeof(struct sockaddr),
					  g_hostname, sizeof(g_hostname),
					  g_serv, sizeof(g_serv),
					  NI_NUMERICSERV | NI_NUMERICHOST);
	ST_EXPECT_EQ(0, res);
	if (res == 0) {
		_print_serv_info(g_hostname, g_serv);
	}
	freeaddrinfo(servinfo);
}
END_TEST_F

/*
 * description: getnameinfo negative
 */
START_TEST_F(getnameinfo_n)
{
	int res = getnameinfo(NULL, 0,
						  g_hostname, sizeof(g_hostname),
						  g_serv, sizeof(g_serv),
						  NI_NUMERICSERV | NI_NUMERICHOST);
	ST_EXPECT_NEQ(0, res);
}
END_TEST_F

/*
 * description: gethostbyname positive
 */
START_TEST_F(gethostbyname_p)
{
	struct hostent *shost;
	shost = gethostbyname(TC_HOST_NAME);
	ST_EXPECT_NEQ(NULL, shost);
	if (shost != NULL) {
		_print_host(shost);
	}
}
END_TEST_F

/*
 * description: gethostbyname negative
 */
START_TEST_F(gethostbyname_n)
{
	struct hostent *shost;
	shost = gethostbyname(NULL);
	ST_EXPECT_EQ(NULL, shost);
}
END_TEST_F

/*
 * description: get socket information
 */
START_TEST_F(netmon_sock)
{
	char *str_sock = NULL;
	int ret = netlib_netmon_sock(str_sock);
	ST_EXPECT_EQ(0, ret);
	if (ret == 0) {
		printf("%s\n", str_sock);
		free(str_sock);
	}
}
END_TEST_F

/*
 * description: get network stack statistics info
 */
START_TEST_F(netmon_stats)
{
	char *str_stats = NULL;
	int ret = netlib_getstats((void *)str_stats);
	ST_EXPECT_EQ(0, ret);
	if (ret == 0) {
		printf("%s\n", str_stats);
		free(str_stats);
	}
}
END_TEST_F

/*
 * Description: get NIC statistics
 */
START_TEST_F(netmon_dev_stats)
{
	char *str_stats = NULL;
	int ret = netlib_netmon_devstats("wlan0", (void **)&str_stats);
	ST_EXPECT_EQ(0, ret);
	if (ret == 0) {
		printf("%s\n", str_stats);
		free(str_stats);
	}
}
END_TEST_F

/*
 * description: set dns server
 */
START_TEST_F(set_dns_p)
{
	struct sockaddr_in dns_addr;
	memset(&dns_addr, 0x0, sizeof(struct sockaddr_in));
	dns_addr.sin_family = AF_INET;
	inet_pton(AF_INET, NT_STR_DNS_ADDR, (void *)&dns_addr.sin_addr);
	int res = netlib_setdnsserver((struct sockaddr *)&dns_addr, -1);
	ST_EXPECT_EQ(0, res);
}
END_TEST_F

/*
 * description: set dns server negative
 */
START_TEST_F(set_dns_n)
{
	int res = netlib_setdnsserver(NULL, -1);
	ST_EXPECT_NEQ(0, res);
}
END_TEST_F

START_TEST_F(dns_queue)
{
	struct sockaddr_in dns_addr;
	memset(&dns_addr, 0x0, sizeof(struct sockaddr_in));
	dns_addr.sin_family = AF_INET;
	inet_pton(AF_INET, NT_STR_DNS_ADDR, (void *)&dns_addr.sin_addr);
	int res = netlib_setdnsserver((struct sockaddr *)&dns_addr, -1);
	ST_EXPECT_EQ(0, res);

	struct addrinfo hints, *local_res;
	int arr_size = sizeof(g_host_list) / sizeof(char *);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	for (int i = 0; i < arr_size; i++) {
		res = getaddrinfo(g_host_list[i], NULL, &hints, &local_res);
		ST_EXPECT_EQ(0, res);
		_print_result(g_host_list[i], local_res);
		freeaddrinfo(local_res);
	}
	sleep(1);
}
END_TEST_F

int network_internal_test(void)
{
#if 0
	ST_SET_PACK(nettest);
	ST_SET_SMOKE1(nettest, NT_TEST_TRIAL, ST_NO_TIMELIMIT, "getaddrinfo p", getaddrinfo_p);
	ST_SET_SMOKE1(nettest, NT_TEST_TRIAL, ST_NO_TIMELIMIT, "getaddrinfo n", getaddrinfo_n);
	ST_SET_SMOKE1(nettest, NT_TEST_TRIAL, ST_NO_TIMELIMIT, "gethostbyname p", gethostbyname_p);
	ST_SET_SMOKE1(nettest, NT_TEST_TRIAL, ST_NO_TIMELIMIT, "gethostbyname n", gethostbyname_n);
	ST_SET_SMOKE1(nettest, NT_TEST_TRIAL, ST_NO_TIMELIMIT, "getnameinfo p", getnameinfo_p);
	ST_SET_SMOKE1(nettest, NT_TEST_TRIAL, ST_NO_TIMELIMIT, "getnameinfo n", getnameinfo_n);
	ST_RUN_TEST(nettest);
	ST_RESULT_TEST(nettest);

	ST_SET_PACK(netmon);
	ST_SET_SMOKE1(netmon, NT_TEST_TRIAL, ST_NO_TIMELIMIT, "get sock info from netmon", netmon_sock);
	ST_SET_SMOKE1(netmon, NT_TEST_TRIAL, ST_NO_TIMELIMIT, "get statistics from netmon", netmon_stats);
	ST_SET_SMOKE1(netmon, NT_TEST_TRIAL, ST_NO_TIMELIMIT, "get NIC statistics", netmon_dev_stats);
	ST_RUN_TEST(netmon);
	ST_RESULT_TEST(netmon);
#endif

	ST_SET_PACK(dns);
	//ST_SET_SMOKE1(dns, NT_TEST_TRIAL, ST_NO_TIMELIMIT, "set dns positive", set_dns_p);
	//ST_SET_SMOKE1(dns, NT_TEST_TRIAL, ST_NO_TIMELIMIT, "set dns negative", set_dns_n);
	ST_SET_SMOKE1(dns, 10000, ST_NO_TIMELIMIT, "set dns negative", dns_queue);
	ST_RUN_TEST(dns);
	ST_RESULT_TEST(dns);

	return 0;
}

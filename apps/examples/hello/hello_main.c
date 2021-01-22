/****************************************************************************
 *
 * Copyright 2016 Samsung Electronics All Rights Reserved.
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
/****************************************************************************
 * examples/hello/hello_main.c
 *
 *   Copyright (C) 2008, 2011-2012 Gregory Nutt. All rights reserved.
 *   Author: Gregory Nutt <gnutt@nuttx.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name NuttX nor the names of its contributors may be
 *    used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <tinyara/config.h>
#include <stdio.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sched.h>
#include <assert.h>
#include <sys/stat.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>

#define BUF_SIZE 1460
#define UDP_PORT 5202
#define PACKET_PERIOD 3000
static int32_t g_no_select = 0;
static inline int calculate(struct timeval *start, struct timeval *end, uint32_t num_packet)
{
	double dstart = (double)start->tv_sec * 1000000.0f + (double)start->tv_usec;
	double dend = (double)end->tv_sec * 1000000.0f + (double)end->tv_usec;
	double elapsed = dend - dstart;

	double received = (double)(num_packet * 1460);

	printf("total %lfMB bandwidth %lfMbps\n", received/(double)(1024 * 1024), received/elapsed * 8.0f);
	return 0;
}

static void recv_select(int sd)
{
	struct sockaddr_in cliaddr;
	socklen_t addrlen = sizeof(struct sockaddr_in);
	int nbytes;
	char buf[BUF_SIZE];
	fd_set rfds;
	fd_set fds;
	int max_fd = sd + 1;
	int32_t pkt_cnt = 0;
	struct timeval start, end;
	FD_ZERO(&fds);
	FD_SET(sd, &fds);

	while (1) {
		rfds = fds;
		int res = select(max_fd, &rfds, NULL, NULL, NULL);
		if (res < 0) {
			printf("[UDPSERV] select error(%d)\n", errno);
			return;
		}
		if (res <= 0) {
			assert(0);
		}
		if (FD_ISSET(sd, &rfds)) {
			nbytes = recvfrom(sd, buf, BUF_SIZE, 0, (struct sockaddr *)&cliaddr, &addrlen);
			if (nbytes < 0) {
				perror("[UDPSERV] recvfrom fail");
				break;
			}
			if (nbytes == 0) {
				printf("[UDPSERV] socket closed from remote\n");
				return;
			}
			pkt_cnt++;
			if (pkt_cnt == 1) {
				printf("[pkbuild] check start\n");
				gettimeofday(&start, NULL);
			} else if (pkt_cnt == PACKET_PERIOD) {
				printf("[pkbuild] check calculate\n");
				gettimeofday(&end, NULL);
				calculate(&start, &end, PACKET_PERIOD);
				pkt_cnt = 0;
			}
		}
	}
}

static void recv_noselect(int sd)
{
	struct sockaddr_in cliaddr;
	socklen_t addrlen = sizeof(struct sockaddr_in);
	int nbytes;
	char buf[BUF_SIZE];
	int32_t pkt_cnt = 0;
	struct timeval start, end;

	while (1) {
		nbytes = recvfrom(sd, buf, BUF_SIZE, 0, (struct sockaddr *)&cliaddr, &addrlen);
		if (nbytes < 0) {
			perror("[UDPSERV] recvfrom fail");
			break;
		}
		if (nbytes == 0) {
			printf("[UDPSERV] socket closed from remote\n");
			return;
		}
		pkt_cnt++;
		if (pkt_cnt == 1) {
			printf("[pkbuild] check start\n");
			gettimeofday(&start, NULL);
		} else if (pkt_cnt == PACKET_PERIOD) {
			printf("[pkbuild] check calculate\n");
			gettimeofday(&end, NULL);
			calculate(&start, &end, PACKET_PERIOD);
			pkt_cnt = 0;
		}
	}
}
static int udp_server_thread(int argc, char *argv[])
{
	struct sockaddr_in servaddr;
	struct sockaddr_in cliaddr;
	int sd;
	socklen_t addrlen = sizeof(struct sockaddr_in);
	int ret = 0;

	sd = socket(PF_INET, SOCK_DGRAM, 0);
	if (sd < 0) {
		perror("[UDPSERV]socket fail");
		return 0;
	}

	printf("[UDPSERV] socket created\n");
	printf("[UDPSERV] debug %d %lu\n", addrlen, sizeof(struct sockaddr));
	memset(&cliaddr, 0, addrlen);
	memset(&servaddr, 0, addrlen);
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(UDP_PORT);

	ret = bind(sd, (struct sockaddr *)&servaddr, addrlen);
	if (ret < 0) {
		perror("[UDPSERV]bind fail\n");
		close(sd);
		return -1;
	}
	printf("[UDPSERV] socket binded\n");
	printf("[UDPSERV] waiting on port %d\n", UDP_PORT);

	if (g_no_select) {
		recv_noselect(sd);
	} else {
		recv_select(sd);
	}
	close(sd);

	return 0;
}

/****************************************************************************
 * hello_main
 ****************************************************************************/

#ifdef CONFIG_BUILD_KERNEL
int main(int argc, FAR char *argv[])
#else
int hello_main(int argc, char *argv[])
#endif
{
	printf("Hello, World!!\n");
	if (argc >= 2) {
		/* pthread_t pid = 0; */
		/* pthread_attr_t attr; */
		/* int res = pthread_attr_init(&attr); */
		/* if (res < 0) { */
		/* 	printf("[pkbuild] pathread attr init fail\n"); */
		/* 	return -1; */
		/* } */
		/* res = pthread_attr_setstacksize(&attr, 4096); */
		/* if (res < 0) { */
		/* 	printf("[pkbuild] set stack size fail\n"); */
		/* 	return -1; */
		/* } */
		/* res = pthread_create(&pid, NULL, udp_server_thread, NULL); */
		/* if (res < 0) { */
		/* 	printf("[pkbuild] create fail\n"); */
		/* } */
		/* /\* res = pthread_setschedprio(pid, 106); *\/ */
		/* /\* if (res < 0) { *\/ */
		/* /\* 	printf("[pkbuild] prio fail\n"); *\/ */
		/* /\* } *\/ */
		/* res = pthread_join(pid, NULL); */
		/* if (res < 0) { */
		/* 	printf("[pkbuild] join fail\n"); */
		/* } */
		if (argc == 3) {
			g_no_select = 1;
		}
		int res = task_create("my app", 107, 4096, udp_server_thread, NULL);
		if (res < 0) {
			printf("[pkbuild] task create fail\n");
		}
	}
	return 0;
}

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

/****************************************************************************
 * hello_main
 ****************************************************************************/
uint32_t g_api_setup_cnt = 0;
uint32_t g_api_event_cnt = 0;
uint32_t g_api_teardown_cnt = 0;
uint32_t g_api_search_cnt = 0;
uint32_t g_api_search_total = 0;

uint32_t g_app_recv_cnt = 0;
uint32_t g_app_recv_total = 0;
uint32_t g_app_recv_max = 0;

uint32_t g_tcpmbox_success = 0;
uint32_t g_tcpmbox_fail = 0;
uint32_t g_tcpmbox_max = 0;
uint32_t g_tcpmbox_total = 0;

uint32_t g_udpmbox_success = 0;
uint32_t g_udpmbox_fail = 0;
uint32_t g_udpmbox_max = 0;
uint32_t g_udpmbox_total = 0;

uint32_t g_link_success = 0;
uint32_t g_link_fail = 0;
uint32_t g_link_total = 0;
uint32_t g_driver_total = 0;

uint32_t g_pbuf_success = 0;
uint32_t g_pbuf_fail = 0;
uint32_t g_pbuf_total_cnt = 0;
uint32_t g_pbuf_driver_fail = 0;

#ifdef CONFIG_BUILD_KERNEL
int main(int argc, FAR char *argv[])
#else
int hello_main(int argc, char *argv[])
#endif
{
	printf("Hello, World!!\n");
	printf("[API] %u %u %u %u %u avg %u\n",
				 g_api_setup_cnt, g_api_teardown_cnt, g_api_event_cnt,
				 g_api_search_cnt, g_api_search_total,
				 ((g_api_search_cnt == 0) ? 0 : g_api_search_total / g_api_search_cnt));
	
	printf("[APP] %u %u max %u avg %u\n",
		   g_app_recv_cnt, g_app_recv_total, g_app_recv_max,
		   ((g_app_recv_cnt == 0) ? 0 : g_app_recv_total / g_app_recv_cnt));
	printf("[tcp] (%u/%u/%u) max %u avg %u\n",
		   g_tcpmbox_success,
		   g_tcpmbox_fail,
		   g_tcpmbox_total, g_tcpmbox_max,
		   ((g_tcpmbox_success == 0) ? 0 : g_tcpmbox_total / g_tcpmbox_success));
	printf("[udp] (%u/%u/%u) max %u avg %u\n",
		   g_udpmbox_success,
		   g_udpmbox_fail,
		   g_udpmbox_total, g_udpmbox_max,
		   ((g_udpmbox_success == 0) ? 0 : g_udpmbox_total / g_udpmbox_success));

	printf("[link] (%u/%u/%u) driver total %u\n",
		   g_link_success, g_link_fail,
		   g_link_total, g_driver_total,
		   ((g_link_success == 0) ? 0 : g_link_total / g_link_success));

	printf("[pbuf] (%u/%u/%u) driver %u\n",
		   g_pbuf_success, g_pbuf_fail, g_pbuf_total_cnt,
		   g_pbuf_driver_fail);

	if (argc == 2) {
		g_api_event_cnt = 0;
		g_api_setup_cnt = 0;
		g_api_teardown_cnt = 0;
		g_api_search_cnt = 0;
		g_api_search_total = 0;
		
		g_app_recv_cnt = 0;
		g_app_recv_total = 0;
		g_app_recv_max = 0;

		g_tcpmbox_success = 0;
		g_tcpmbox_fail = 0;
		g_tcpmbox_max = 0;
		g_tcpmbox_total = 0;

		g_udpmbox_success = 0;
		g_udpmbox_fail = 0;
		g_udpmbox_max = 0;
		g_udpmbox_total = 0;

		g_link_success = 0;
		g_link_fail = 0;
		g_link_total = 0;
		g_driver_total = 0;

		g_pbuf_success = 0;
		g_pbuf_fail = 0;
		g_pbuf_total_cnt = 0;
		g_pbuf_driver_fail = 0;
	}
	return 0;
}

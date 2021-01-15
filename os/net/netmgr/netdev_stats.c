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

#include <tinyara/config.h>
#include <debug.h>

uint32_t g_link_recv_byte = 0;
uint32_t g_link_recv_cnt = 0;
uint32_t g_link_recv_err = 0;
uint32_t g_link_memp_err_cnt = 0;
uint32_t g_link_pass_err_cnt = 0;
uint32_t g_link_mbox_err_cnt = 0;

uint32_t g_app_recv_byte = 0;
uint32_t g_app_recv_cnt = 0;

uint32_t g_ip_recv_cnt = 0;
uint32_t g_eth_recv_cnt = 0;
uint32_t g_netmgr_valid_recv_cnt = 0;
uint32_t g_iperf_ooo_cnt = 0;

uint32_t g_udp_mbox_err = 0;

void netstats_display(void)
{
	printf("[driver] mbox err %u\n", g_link_recv_err);
	printf("[driver] total recv %u\t%u\n", g_link_recv_byte, g_link_recv_cnt);
	printf("[netmgr] total recv %u\n", g_netmgr_valid_recv_cnt);
	printf("[link] %u %u %u \n", g_link_memp_err_cnt, g_link_pass_err_cnt, g_link_mbox_err_cnt);
	printf("[eth] total recv %u\n", g_eth_recv_cnt);
	printf("[ip] total recv %u\n", g_ip_recv_cnt);
	printf("[udp] post fail count %u\n", g_udp_mbox_err);
	printf("[app] total recv %u\t%u\n", g_app_recv_byte, g_app_recv_cnt);
	printf("[iperf] out of order count %u\n", g_iperf_ooo_cnt);

}

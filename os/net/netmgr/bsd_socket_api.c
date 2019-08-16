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
/*
 * Copyright (c) 2016 Samsung Electronics co. ltd
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack's wrapper
 *
 * Author: Byoungtae Cho <bt.cho@samsung.com>
 *
 */

/**
 * @file
 * Sockets BSD-Like API wrapper module
 *
 */

#include <tinyara/config.h>
#include <tinyara/cancelpt.h>

#ifdef CONFIG_NET

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>

int bind(int s, const struct sockaddr *name, socklen_t namelen)
{
	struct netmgr_stack_ops *s_ops = get_netstack();
	return s_ops->bind(s, name, namelen);
}

int accept(int s, struct sockaddr *addr, socklen_t *addrlen)
{
	(void)enter_cancellation_point();
	struct netmgr_stack_ops *s_ops = get_netstack();
	int res = s_ops->accept(s, addr, addrlen);
	leave_cancellation_point();
	return res;
}

int shutdown(int s, int how)
{
	struct netmgr_stack_ops *s_ops = get_netstack();
	return s_ops->shutdown(s, how);
}

int connect(int s, const struct sockaddr *name, socklen_t namelen)
{
	/* Treat as a cancellation point */
	(void)enter_cancellation_point();
	struct netmgr_stack_ops *s_ops = get_netstack();
	int res = s_ops->connect(s, name, namelen);
	leave_cancellation_point();
	return res;
}

int getsockname(int s, struct sockaddr *name, socklen_t *namelen)
{
	struct netmgr_stack_ops *s_ops = get_netstack();
	return s_ops->getsockname(s, name, namelen);
}

int getpeername(int s, struct sockaddr *name, socklen_t *namelen)
{
	struct netmgr_stack_ops *s_ops = get_netstack();
	return s_ops->getpeername(s, name, namelen);
}

int setsockopt(int s, int level, int optname, const void *optval, socklen_t optlen)
{
	struct netmgr_stack_ops *s_ops = get_netstack();
	return s_ops->setsockopt(s, level, optname, optval, optlen);
}

int getsockopt(int s, int level, int optname, void *optval, socklen_t *optlen)
{
	struct netmgr_stack_ops *s_ops = get_netstack();
	return s_ops->getsockopt(s, level, optname, optval, optlen);
}

int listen(int s, int backlog)
{
	struct netmgr_stack_ops *s_ops = get_netstack();
	return s_ops->listen(s, backlog);
}

ssize_t recv(int s, void *mem, size_t len, int flags)
{
	/* Treat as a cancellation point */
	(void)enter_cancellation_point();
	struct netmgr_stack_ops *s_ops = get_netstack();
	int res = s_ops->recv(s, mem, len, flags);
	leave_cancellation_point();
	return res;
}

ssize_t recvfrom(int s, void *mem, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen)
{
	/* Treat as a cancellation point */
	(void)enter_cancellation_point();
	struct netmgr_stack_ops *s_ops = get_netstack();
	int res = s_ops->recvfrom(s, mem, len, flags, from, fromlen);
	leave_cancellation_point();
	return res;
}

/****************************************************************************
 * Function: recvmsg
 *
 * Description:
 *   The recvmsg() call is identical to recvfrom() with a NULL from parameter.
 *
 * Parameters:
 *   sockfd   Socket descriptor of socket
 *   buf      Buffer to receive data
 *   len      Length of buffer
 *   flags    Receive flags
 *
 * Returned Value:
 *  (see recvfrom)
 *
 * Assumptions:
 *
 ****************************************************************************/
ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags)
{
	// ToDo: It only supports limited features of sendmsg
	struct netmgr_stack_ops *s_ops = get_netstack();
	return s_ops->recvmsg(sockfd, msg, flags);
}

ssize_t send(int s, const void *data, size_t size, int flags)
{
	/* Treat as a cancellation point */
	(void)enter_cancellation_point();
	struct netmgr_stack_ops *s_ops = get_netstack();
	int res = s_ops->send(s, data, size, flags);
	leave_cancellation_point();
	return res;
}

ssize_t sendto(int s, const void *data, size_t size, int flags, const struct sockaddr *to, socklen_t tolen)
{
	/* Treat as a cancellation point */
	(void)enter_cancellation_point();
	struct netmgr_stack_ops *s_ops = get_netstack();
	int res = s_ops->sendto(s, data, size, flags, to, tolen);
	leave_cancellation_point();
	return res;
}

/****************************************************************************
 * Function: sendmsg
 *
 * Description:
 *   The sendmsg() call is identical to sendto() with a NULL from parameter.
  *
 * Parameters:
 *   sockfd   Socket descriptor of socket
 *   buf      Buffer to send data
 *   len      Length of buffer
 *   flags    Receive flags
 *
 * Returned Value:
 *  (see sendto)
 *
 * Assumptions:
 *
 ****************************************************************************/
ssize_t sendmsg(int sockfd, struct msghdr *msg, int flags)
{
	// ToDo: It only supports limited features of sendmsg
	struct netmgr_stack_ops *s_ops = get_netstack();
	int res = s_ops->sendmsg(sockfd, msg, flags);

}


int socket(int domain, int type, int protocol)
{
	struct netmgr_stack_ops *s_ops = get_netstack();
	return s_ops->socket(domain, type, protocol);
}
#endif

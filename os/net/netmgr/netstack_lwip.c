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
#include "netstack.h"

static int _socket_argument_validation(int domain, int type, int protocol)
{
	if (domain != AF_INET && domain != AF_INET6 && domain != AF_UNSPEC) {
		return -1;
	}
	switch (protocol) {
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
		if (type != SOCK_DGRAM && type != SOCK_RAW) {
			return -1;
		}
		break;
	case IPPROTO_TCP:
		if (type != SOCK_STREAM) {
			return -1;
		}
		break;
	case IPPROTO_ICMP:
	case IPPROTO_IGMP:
	case IPPROTO_ICMPV6:
		if (type != SOCK_RAW) {
			return -1;
		}
		break;
	case IPPROTO_IP:
		if (type == SOCK_RAW) {
			return -1;
		}
		break;
	default:
		return -1;
		break;
	}
	return 0;
}

/*
 * ops functions
 */
static int lwip_ns_close(int sockfd)
{
	return lwip_close(sockfd);
}

static int lwip_ns_dupsd(int sockfd)
{
	struct socket *sock1 = NULL;
	struct socket *sock2 = NULL;
	struct netconn *conn = NULL;
	int sockfd2;
	int err;
	int ret;

	/* Lock the scheduler throughout the following */
	sched_lock();

	/* Get the socket structure underlying sockfd */

	sock1 = get_socket(sockfd);

	/* Verify that the sockfd corresponds to valid, allocated socket */

	if (!sock1) {
		err = EBADF;
		goto errout;
	}

	/* Allocate a new netconn with same type as that of sock1 */

	conn = netconn_new(sock1->conn->type);

	sockfd2 = alloc_socket(conn, 0);
	if (sockfd2 < 0) {
		err = ENFILE;
		goto errout;
	}

	/* Get the socket structure underlying the new descriptor */

	sock2 = (struct socket *)get_socket(sockfd2);
	if (!sock2) {
		err = ENOSYS;			/* should not happen */
		goto errout;
	}

	/* Duplicate the socket state */

	ret = lwip_ns_clone(sock1, sock2);
	if (ret < 0) {
		err = -ret;
		goto errout;

	}

	sched_unlock();
	return sockfd2;

errout:
	sched_unlock();
	errno = err;
	return ERROR;
}

static int lwip_ns_dupsd2(int sockfd1, int sockfd2)
{
	struct socket *sock1;
	struct socket *sock2;
	int err;
	int ret;

	/* Lock the scheduler throughout the following */

	sched_lock();

	/* Get the socket structures underly both descriptors */

	sock1 = (struct socket *)get_socket(sockfd1);
	sock2 = (struct socket *)get_socket(sockfd2);

	/* Verify that the sockfd1 and sockfd2 both refer to valid socket
	 * descriptors and that sockfd1 has valid allocated conn
	 */

	if (!sock1 || !sock2) {
		err = EBADF;
		goto errout;
	}

	/* If sockfd2 also has valid allocated conn, then we will have to
	 * close it!
	 */

	if (sock2->conn) {
		netconn_delete(sock2->conn);
		sock2->conn = NULL;
	}

	/* Duplicate the socket state */

	ret = lwip_ns_clone(sock1, sock2);
	if (ret < 0) {
		err = -ret;
		goto errout;
	}

	sched_unlock();
	return OK;

errout:
	sched_unlock();
	errno = err;
	return ERROR;
}

static int lwip_ns_clone(FAR struct socket *psock1, FAR struct socket *psock2)
{
	int ret = OK;

	/* Todo: Parts of this operation need to be atomic?? */
	/* Duplicate the socket state */
	sock2->conn = sock1->conn;	/* Netconn callback */
	sock2->lastdata = sock1->lastdata;	/* data that was left from the previous read */
	sock2->lastoffset = sock1->lastoffset;	/* offset in the data that was left from the previous read */
	sock2->rcvevent = sock1->rcvevent;	/*  number of times data was received, set by event_callback(),
										   tested by the receive and select / poll functions */
	sock2->sendevent = sock1->sendevent;	/* number of times data was ACKed (free send buffer), set by event_callback(),
											   tested by select / poll */
	sock2->errevent = sock1->errevent;	/* error happened for this socket, set by event_callback(), tested by select / poll */

	sock2->err = sock1->err;	/* last error that occurred on this socket */

	sock2->select_waiting = sock1->select_waiting;	/* counter of how many threads are waiting for this socket using select */
	sock2->conn->crefs++;

	return ret;
}

static int lwip_ns_checksd(int sd, int oflags)
{
	struct socket *sock = (struct socket *)get_socket(sd);

	/* Verify that the sockfd corresponds to valid, allocated socket */

	if (!sock) {
		nvdbg("No valid socket for sd: %d\n", sd);
		return -EBADF;
	}

	/* NOTE:  We permit the socket FD to be "wrapped" in a stream as
	 * soon as the socket descriptor is created by socket().  Therefore
	 * (1) we don't care if the socket is connected yet, and (2) there
	 * are no access restrictions that can be enforced yet.
	 */
	return 0;
}

static int lwip_ns_ioctl(int sockfd, int cmd, unsigned long arg)
{
	return lwip_ioctl(sockfd, cmd, arg);
}



static int lwip_ns_vfcntl(int sockfd, int cmd, va_list ap)
{
	return lwip_fcntl(sockfd, cmd, ap);
}

static int lwip_ns_socket(int domain, int type, int protocol)
{
	return lwip_socket(domain, type, protocol)
}

static int lwip_ns_bind(int s, const struct sockaddr *name, socklen_t namelen)
{
	return lwip_bind(s, name, namelen);
}


static int lwip_ns_accept(int s, struct sockaddr *addr, socklen_t *addrlen)
{
	return lwip_accept(s, addr, addrlen);
}


static int lwip_ns_listen(int s, int backlog)
{
	return lwip_listen(s, backlog);
}


static int lwip_ns_shutdown(int s, int how)
{
	return lwip_shutdown(s, how);
}


static ssize_t lwip_ns_recv(int s, void *mem, size_t len, int flags)
{
	return lwip_recv(s, mem, len, flags);
}


static ssize_t lwip_ns_recvfrom(int s, void *mem, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen)
{
	return lwip_recvfrom(s, mem, len, flags, from, fromlen);
}


static ssize_t lwip_ns_send(int s, const void *data, size_t size, int flags)
{
	return lwip_send(s, data, size, flags);
}


static ssize_t lwip_ns_sendto(int s, const void *data, size_t size, int flags, const struct sockaddr *to, socklen_t tolen)
{
	return lwip_sendto(s, data, size, flags, to, tolen);
}


static int lwip_ns_getsockname(int s, struct sockaddr *name, socklen_t *namelen)
{
	return lwip_getsockname(s, name, namelen);
}


static int lwip_ns_getpeername(int s, struct sockaddr *name, socklen_t *namelen)
{
	return lwip_getpeername(s, name, namelen);
}


static int lwip_ns_setsockopt(int s, int level, int optname, const void *optval, socklen_t optlen)
{
	return lwip_setsockopt(s, level, optname, optval, optlen);
}


static int lwip_ns_getsockopt(int s, int level, int optname, void *optval, socklen_t *optlen)
{
	return lwip_getsockopt(s, level, optname, optval, optlen);
}


static ssize_t lwip_ns_recvmsg(int sockfd, struct msghdr *msg, int flags)
{
	uint8_t *buf = (uint8_t *)(msg->msg_iov->iov_base);
	size_t len = msg->msg_iov->iov_len;
	struct sockaddr *from = (struct sockaddr *)msg->msg_name;
	socklen_t *addrlen = &(msg->msg_namelen);
	msg->msg_controllen = 0;

	return recvfrom(sockfd, buf, len, flags, from, addrlen);
}


static ssize_t lwip_ns_sendmsg(int s, struct msghdr *msg, int flags)
{
	uint8_t *buf = (uint8_t *)(msg->msg_iov->iov_base);
	size_t len = msg->msg_iov->iov_len;
	struct sockaddr *to = (struct sockaddr *)msg->msg_name;
	int *addrlen = (int *)&(msg->msg_namelen);

	return sendto(sockfd, buf, len, flags, to, (socklen_t) *addrlen);
}

static int lwip_ns_init(void *data)
{
	lwip_init();
	return 0;
}


static int lwip_ns_deinit(void *data)
{
	return 0;
}


static int lwip_ns_start(void *data)
{
	tcpip_init(NULL, NULL);
	return 0;
}


static int lwip_ns_stop(void *data)
{
	return 0;
}

static int lwip_ns_addroute(struct rtentry *entry)
{
	if (!entry || !entry->rt_target || !entry->rt_netmask) {
		return -EINVAL;
	}

	// ToDo
	return -ENOTTY;
}

static int lwip_ns_delroute(struct rtentry *entry)
{
	if (!entry || !entry->rt_target || !entry->rt_netmask) {
		return -EINVAL;
	}

	// ToDo
	return -ENOTTY;
}

static struct netmgr_stack_ops g_lwip_stack_ops = {
	lwip_ns_init,
	lwip_ns_deinit,
	lwip_ns_start,
	lwip_ns_stop,
	lwip_ns_close,
	lwip_ns_dup,
	lwip_ns_dup2,
	lwip_ns_clone,
	lwip_ns_checksd,
	lwip_ns_ioctl,
	lwip_ns_fcntl,
	lwip_ns_socket,
	lwip_ns_bind,
	lwip_ns_accept,
	lwip_ns_listen,
	lwip_ns_shutdown,
	lwip_ns_recv,
	lwip_ns_recvfrom,
	lwip_ns_recvmsg,
	lwip_ns_send,
	lwip_ns_sendto,
	lwip_ns_sendmsg,
	lwip_ns_getsockname,
	lwip_ns_getpeername,
	lwip_ns_setsockopt,
	lwip_ns_getsockopt,
	lwip_ns_addroute,
	lwip_ns_delroute
};

static struct netstack *g_lwip_stack = {
	&g_lwip_stack_ops,
	NULL
};

struct struct netstack *get_netstack_lwip(void)
{
	return &g_lwip_stack;
}

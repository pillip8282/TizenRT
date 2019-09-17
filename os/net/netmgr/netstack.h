#ifndef _NETMGR_NETSTACK_H__
#define _NETMGR_NETSTACK_H__

#include <poll.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <net/route.h>
#include <tinyara/netmgr/net_vfs.h>

struct netstack_ops {
	// start, stop
	int (*init)(void *data);
	int (*deinit)(void *data);
	int (*start)(void *data);
	int (*stop)(void *data);

	// VFS
	int (*close)(int sockfd);
	int (*dup)(int sockfd);
	int (*dup2)(int sockfd1, int sockfd2);
	int (*clone)(struct socket *sock1, struct socket *sock2);
	int (*checksd)(int sd, int oflags);
	int (*ioctl)(int sockfd, int cmd, unsigned long arg); // stack specific option
	int (*fcntl)(int sockfd, int cmd, va_list ap);
	int (*poll)(int fd, struct pollfd *fds, bool setup);
	// BSD Socket API
	int (*socket)(int domain, int type, int protocol);
	int (*bind)(int s, const struct sockaddr *name, socklen_t namelen);
	int (*connect)(int s, const struct sockaddr *name, socklen_t namelen);
	int (*accept)(int s, struct sockaddr *addr, socklen_t *addrlen);
	int (*listen)(int s, int backlog);
	int (*shutdown)(int s, int how);
	ssize_t (*recv)(int s, void *mem, size_t len, int flags);
	ssize_t (*recvfrom)(int s, void *mem, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen);
	ssize_t (*recvmsg)(int s, struct msghdr *msg, int flags);
	ssize_t (*send)(int s, const void *data, size_t size, int flags);
	ssize_t (*sendto)(int s, const void *data, size_t size, int flags, const struct sockaddr *to, socklen_t tolen);
	ssize_t (*sendmsg)(int s, struct msghdr *msg, int flags);
	int (*getsockname)(int s, struct sockaddr *name, socklen_t *namelen);
	int (*getpeername)(int s, struct sockaddr *name, socklen_t *namelen);
	int (*setsockopt)(int s, int level, int optname, const void *optval, socklen_t optlen);
	int (*getsockopt)(int s, int level, int optname, void *optval, socklen_t *optlen);

	// etc
#ifdef CONFIG_NET_ROUTE
	int (*addroute)(struct rtentry *entry);
	int (*delroute)(struct rtentry *entry);
#endif
};

struct netstack {
	struct netstack_ops *ops;
	void *data;
};

struct netstack *get_netstack(void);

#endif //  _NETMGR_NETSTACK_H__

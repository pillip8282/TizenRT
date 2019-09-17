#include <tinyara/config.h>
/*  g_socket exactly map to lwip_sock list */
static struct socket g_socket_list[CONFIG_NSOCKET_DESCRIPTORS];

struct socket *net_get_socket(int sd)
{
	return &g_socket_list[sd];
}

struct socket *net_alloc_socket(enum netconn_type type, int accepted)
{
	struct netconn *conn = netconn_new(sock1->conn->type);

	int sockfd2 = alloc_socket(conn, 0);
	if (sockfd2 < 0) {
		// todo_net : delete netconn
		return NULL;
	}
	NET_SOCK(g_socket_list[sockfd2])->sock = get_socket(sockfd2);

	return &g_socket_list[sockfd2];
}

int net_clone_socket(struct socket *src, struct socket *dest)
{

}

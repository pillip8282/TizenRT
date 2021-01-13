#ifndef __VWIFI_HANDLER_H__
#define __VWIFI_HANDLER_H__

#define VWIFI_LOG lldbg
#define VWIFI_ENTRY VWIFI_LOG("-->T%d %s:%d\n", getpid(), __FUNCTION__, __LINE__)
#define VWIFI_ERROR(res) VWIFI_LOG("T%d error %d %d %s:%d\n", getpid(), res, errno, __FUNCTION__, __LINE__)

typedef enum {
	VWIFI_MSG_INIT,
	VWIFI_MSG_DEINIT,
	VWIFI_MSG_SCANAP,
	VWIFI_MSG_CONNECTAP,
	VWIFI_MSG_DISCONENCTAP,
	VWIFI_MSG_GETINFO,
	VWIFI_MSG_STARTSTA,
	VWIFI_MSG_STARTSOFTAP,
	VWIFI_MSG_STOPSOFTAP,
	VWIFI_MSG_SETAUTOCONNECT,
} vwifi_req_e;

struct vwifi_req {
	vwifi_req_e type;
	int res;
};

struct vwifi_msg {
	struct vwifi_req *req;
	void *signal;
};

int vwifi_handle_message(struct vwifi_req *req);
#endif // #define __VWIFI_HANDLER_H__

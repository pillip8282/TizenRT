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
#ifndef __INCLUDE_TINYARA_LWNL80211_H__
#define __INCLUDE_TINYARA_LWNL80211_H__

#include <sys/ioctl.h>
#include <stdint.h>
#include <stdbool.h>
#include <mqueue.h>
#include <semaphore.h>
#include <debug.h>

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/
#define LWNL80211_PATH "/dev/lwnl80211"

#define LWNL80211_TAG "[LWNL80211]"

#define LWNL80211_ERR                                                            \
	do {                                                                         \
		nldbg(LWNL80211_TAG"[ERR] %s: %d line err(%s)\n",                        \
				  __FILE__, __LINE__, strerror(errno));                          \
	} while (0)

#define LWNL80211_ENTER                                                          \
	do {                                                                         \
		nldbg(LWNL80211_TAG"--->%s:%d\n", __FILE__, __LINE__);                   \
	} while (0)

#define LWNL80211_LEAVE                                                          \
	do {                                                                         \
		nldbg(LWNL80211_TAG"<---%s:%d\n", __FILE__, __LINE__);                   \
	} while (0)

/* Light-weight netlink domain definition */
#define AF_LWNL 1

/*  Event type */
#define LWNL_ROUTE 1

#define LWNL80211_MQUEUE_PRIORITY        100
#define LWNL80211_MQUEUE_MAX_DATA_LEN    1024
#define LWNL80211_MQUEUE_MAX_DATA_NUM    128

#define LWNL80211_MACADDR_LEN            6
#define LWNL80211_MACADDR_STR_LEN        17
#define LWNL80211_SSID_LEN               32
#define LWNL80211_PASSPHRASE_LEN         64

/* IOCTL commands ***********************************************************/

/* Common operations */
#define LWNL80211_INIT                          _LWNLIOC(1)
#define LWNL80211_DEINIT                        _LWNLIOC(2)
#define LWNL80211_SCAN_AP                       _LWNLIOC(3)
#define LWNL80211_GET_INFO                      _LWNLIOC(4)
#define LWNL80211_REGISTER_CALLBACK             _LWNLIOC(5)
#define LWNL80211_SET_AUTOCONNECT               _LWNLIOC(6)

/* STA operations */
#define LWNL80211_START_STA                     _LWNLIOC(7)
#define LWNL80211_CONNECT_AP                    _LWNLIOC(8)
#define LWNL80211_DISCONNECT_AP                 _LWNLIOC(9)

/* AP operations */
#define LWNL80211_START_SOFTAP                  _LWNLIOC(10)
#define LWNL80211_STOP_SOFTAP                   _LWNLIOC(11)

/* Mqueue */
#define LWNL80211_REGISTERMQ                    _LWNLIOC(12)
#define LWNL80211_UNREGISTERMQ                  _LWNLIOC(13)

/****************************************************************************
 * Public Types
 ****************************************************************************/
typedef enum {
	LWNL80211_FAIL = -1,
	LWNL80211_SUCCESS,
	LWNL80211_INVALID_ARGS,
	LWNL80211_TIMEOUT,
	LWNL80211_BUSY,
	LWNL80211_FILE_ERROR,
	LWNL80211_ALREADY_CONNECTED,
} lwnl80211_result_e;

typedef enum {
	LWNL80211_STA_CONNECTED,
	LWNL80211_STA_CONNECT_FAILED,
	LWNL80211_STA_DISCONNECTED,
	LWNL80211_SOFTAP_STA_JOINED,
	LWNL80211_SOFTAP_STA_LEFT,
	LWNL80211_SCAN_DONE,
	LWNL80211_SCAN_FAILED,
	LWNL80211_EXIT,
	LWNL80211_UNKNOWN,
} lwnl80211_cb_status;

typedef enum {
	LWNL80211_IEEE_80211_LEGACY,             /**<  IEEE 802.11a/g/b          */
	LWNL80211_IEEE_80211_A,                  /**<  IEEE 802.11a              */
	LWNL80211_IEEE_80211_B,                  /**<  IEEE 802.11b              */
	LWNL80211_IEEE_80211_G,                  /**<  IEEE 802.11g              */
	LWNL80211_IEEE_80211_N,                  /**<  IEEE 802.11n              */
	LWNL80211_IEEE_80211_AC,                 /**<  IEEE 802.11ac             */
	LWNL80211_NOT_SUPPORTED,                 /**<  Driver does not report    */
} lwnl80211_standard_type_e;

typedef enum {
	LWNL80211_AUTH_OPEN,					 /**<  open mode                                 */
	LWNL80211_AUTH_WEP_SHARED,				 /**<  use shared key (wep key)                  */
	LWNL80211_AUTH_WPA_PSK,				     /**<  WPA_PSK mode                              */
	LWNL80211_AUTH_WPA2_PSK,				 /**<  WPA2_PSK mode                             */
	LWNL80211_AUTH_WPA_AND_WPA2_PSK,		 /**<  WPA_PSK and WPA_PSK mixed mode            */
	LWNL80211_AUTH_WPA_PSK_ENT,			     /**<  Enterprise WPA_PSK mode                   */
	LWNL80211_AUTH_WPA2_PSK_ENT,			 /**<  Enterprise WPA2_PSK mode                  */
	LWNL80211_AUTH_WPA_AND_WPA2_PSK_ENT,	 /**<  Enterprise WPA_PSK and WPA_PSK mixed mode */
	LWNL80211_AUTH_IBSS_OPEN,                /**<  IBSS ad-hoc mode                          */
	LWNL80211_AUTH_WPS,					     /**<  WPS mode                                  */
	LWNL80211_AUTH_UNKNOWN,				     /**<  unknown type                              */
} lwnl80211_ap_auth_type_e;

typedef enum {
	LWNL80211_CRYPTO_NONE,					 /**<  none encryption                           */
	LWNL80211_CRYPTO_WEP_64,				 /**<  WEP encryption wep-40                     */
	LWNL80211_CRYPTO_WEP_128,				 /**<  WEP encryption wep-104                    */
	LWNL80211_CRYPTO_AES,					 /**<  AES encryption                            */
	LWNL80211_CRYPTO_TKIP,					 /**<  TKIP encryption                           */
	LWNL80211_CRYPTO_TKIP_AND_AES,			 /**<  TKIP and AES mixed encryption             */
	LWNL80211_CRYPTO_AES_ENT,				 /**<  Enterprise AES encryption                 */
	LWNL80211_CRYPTO_TKIP_ENT,				 /**<  Enterprise TKIP encryption                */
	LWNL80211_CRYPTO_TKIP_AND_AES_ENT,		 /**<  Enterprise TKIP and AES mixed encryption  */
	LWNL80211_CRYPTO_UNKNOWN,				 /**<  unknown encryption                        */
} lwnl80211_ap_crypto_type_e;

typedef enum {
	LWNL80211_DISCONNECTED,			/**<  wifi is disconnected  */
	LWNL80211_CONNECTED,			/**<  connected             */
	LWNL80211_SOFTAP_MODE,			/**<  soft ap mode          */
} lwnl80211_status_e;

#define LWNL_NI_NAME_SIZE 7
typedef struct {
	void *data;
	uint32_t data_len;
	lwnl80211_result_e res;
	uint8_t name[LWNL_NI_NAME_SIZE];
} lwnl80211_data;

typedef struct {
	char ssid[LWNL80211_SSID_LEN + 1];              /**<  Service Set Identification         */
	unsigned int ssid_length;                       /**<  Service Set Identification Length  */
	char passphrase[LWNL80211_PASSPHRASE_LEN + 1];  /**<  ap passphrase(password)            */
	unsigned int passphrase_length;                 /**<  ap passphrase length               */
	lwnl80211_ap_auth_type_e ap_auth_type;          /**<  @ref lwnl80211_ap_auth_type        */
	lwnl80211_ap_crypto_type_e ap_crypto_type;      /**<  @ref lwnl80211_ap_crypto_type      */
} lwnl80211_ap_config_s;

typedef struct {
	unsigned int channel;                                  /**<  Radio channel that the AP beacon was received on       */
	char ssid[LWNL80211_SSID_LEN + 1];                     /**<  Service Set Identification (i.e. Name of Access Point) */
	unsigned int ssid_length;                              /**<  The length of Service Set Identification               */
	unsigned char bssid[LWNL80211_MACADDR_STR_LEN + 1];    /**<  MAC address (xx:xx:xx:xx:xx:xx) of Access Point        */
	unsigned int max_rate;                                 /**<  Maximum data rate in kilobits/s                        */
	int rssi;                                              /**<  Receive Signal Strength Indication in dBm              */
	lwnl80211_standard_type_e phy_mode;                    /**< Supported MAC/PHY standard                              */
	lwnl80211_ap_auth_type_e ap_auth_type;                 /**<  @ref lwnl80211_ap_auth_type                            */
	lwnl80211_ap_crypto_type_e ap_crypto_type;             /**<  @ref lwnl80211_ap_crypto_type                          */
} lwnl80211_ap_scan_info_s;

typedef struct {
	unsigned int channel;                                  /**<  soft ap wifi channel               */
	char ssid[LWNL80211_SSID_LEN + 1];                     /**<  Service Set Identification         */
	unsigned int ssid_length;                              /**<  Service Set Identification Length  */
	char passphrase[LWNL80211_PASSPHRASE_LEN + 1];         /**<  ap passphrase(password)            */
	unsigned int passphrase_length;                        /**<  ap passphrase length               */
	lwnl80211_ap_auth_type_e ap_auth_type;                 /**<  @ref lwnl80211_ap_auth_type        */
	lwnl80211_ap_crypto_type_e ap_crypto_type;             /**<  @ref lwnl80211_ap_crypto_type      */
	void (*inform_new_sta_join)(void);                      /**< @ref new station joining softAP    */
} lwnl80211_softap_config_s;

typedef struct lwnl80211_scan_list {
	lwnl80211_ap_scan_info_s ap_info;
	struct lwnl80211_scan_list *next;
} lwnl80211_scan_list_s;

typedef struct {
	uint32_t ip4_address;                                  /**<  ip4 address                               */
	unsigned char mac_address[LWNL80211_MACADDR_LEN];      /**<  MAC address of wifi interface             */
	int rssi;                                              /**<  Receive Signal Strength Indication in dBm */
	lwnl80211_status_e wifi_status;                        /**<  @ref lwnl80211_status                     */
} lwnl80211_info;


typedef struct {
	lwnl80211_cb_status status;
	union {
		void *data;
		lwnl80211_ap_scan_info_s ap_info;
	} u;
	uint32_t data_len;
	bool md;
} lwnl80211_cb_data;


struct netdev;
struct lwnl80211_ops {
	/*  block call */
	CODE lwnl80211_result_e (*init)(struct netdev *dev);
	/*  block call */
	CODE lwnl80211_result_e (*deinit)(struct netdev *dev);
	/*  non-block */
	CODE lwnl80211_result_e (*scan_ap)(struct netdev *dev, void *arg);
	/*  non-block */
	CODE lwnl80211_result_e (*connect_ap)(struct netdev *dev, lwnl80211_ap_config_s *config, void *arg);
	/*  non-block */
	CODE lwnl80211_result_e (*disconnect_ap)(struct netdev *dev, void *arg);
	/*  block */
	CODE lwnl80211_result_e (*get_info)(struct netdev *dev, lwnl80211_info *info);
	/*  block */
	CODE lwnl80211_result_e (*start_sta)(struct netdev *dev);
	/*  block */
	CODE lwnl80211_result_e (*start_softap)(struct netdev *dev, lwnl80211_softap_config_s *config);
	/*  block */
	CODE lwnl80211_result_e (*stop_softap)(struct netdev *dev);
	/*  block */
	CODE lwnl80211_result_e (*set_autoconnect)(struct netdev *dev, uint8_t chk);
	/*  block */
	CODE lwnl80211_result_e (*drv_ioctl)(struct netdev *dev, int cmd, unsigned long arg);
};


struct lwnl80211_upperhalf_s;
struct lwnl80211_lowerhalf_s {
	struct lwnl80211_upperhalf_s *parent;
};

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/* Registrations */
int lwnl80211_register(struct lwnl80211_lowerhalf_s *lower);
// There is no use case to remove the lwnl80211 device.
//int lwnl80211_unregister(void *dev);

int lwnl80211_postmsg(lwnl80211_cb_status status, void *buffer);

#endif /* __INCLUDE_TINYARA_LWNL80211_H__ */

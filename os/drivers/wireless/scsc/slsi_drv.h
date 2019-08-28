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
#ifndef __INCLUDE_SLSIDRV_H__
#define __INCLUDE_SLSIDRV_H__

#include <tinyara/lwnl/lwnl80211.h>

/****************************************************************************
 * Public Types
 ****************************************************************************/

/****************************************************************************
 * Public Functions
 ****************************************************************************/
lwnl80211_result_e slsidrv_init(struct netdev *dev);
lwnl80211_result_e slsidrv_deinit(struct netdev *dev);
lwnl80211_result_e slsidrv_scan_ap(struct netdev *dev, void *arg);
lwnl80211_result_e slsidrv_connect_ap(struct netdev *dev, lwnl80211_ap_config_s *ap_connect_config, void *arg);
lwnl80211_result_e slsidrv_disconnect_ap(struct netdev *dev, void *arg);
lwnl80211_result_e slsidrv_get_info(struct netdev *dev, lwnl80211_info *wifi_info);
lwnl80211_result_e slsidrv_start_softap(struct netdev *dev, lwnl80211_softap_config_s *softap_config);
lwnl80211_result_e slsidrv_start_sta(struct netdev *dev);
lwnl80211_result_e slsidrv_stop_softap(struct netdev *dev);
lwnl80211_result_e slsidrv_set_autoconnect(struct netdev *dev, uint8_t check);

/* Registrations */

#endif /*  __INCLUDE_SLSIDRV_H__ */

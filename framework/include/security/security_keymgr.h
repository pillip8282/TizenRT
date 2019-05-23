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
/**
 * @defgroup Security Security
 * @ingroup Security
 * @brief Provides APIs for Security
 * @{
 */
/**
 * @file security/security_keymgr.h
 * @brief Provides Key manager APIs for Security
 */
#ifndef _SECURITY_API_KEYMGR_H__
#define _SECURITY_API_KEYMGR_H__

#include "security_common.h"

/**
 * @brief Generate symmetric and asymmetric keys.
 * @details @b #include <security/security_api.h>
 * @param[in] hnd The ID which uniquely accesses security resource
 * @param[in] algo Key algorithm.
 * @param[in] key_name Key name in secure storage
 * @return On success, SECURITY_OK (i.e., 0) is returned. On failure, non-zero value is returned.
 *
 * @since TizenRT v2.1
 */
security_error keymgr_generate_key(security_handle hnd, security_key_type algo, const char *key_name);

/**
 * @brief Store external keys which the user generated in secure storage.
 * @details @b #include <security/security_api.h>
 * @param[in] hnd The ID which uniquely accesses security resource.
 * @param[in] algo Key algorithm.
 * @param[in] key_name Key name in secure storage.
 * @param[in] pubkey External public key data will be stored in secure storage.
 * @param[out] prikey External private key data will be stored in secure storage.
 * @return On success, SECURITY_OK (i.e., 0) is returned. On failure, non-zero value is returned.
 *
 * @since TizenRT v2.1
 */
security_error keymgr_set_key(security_handle hnd, security_key_type algo, const char *key_name, security_data *pubkey, security_data *prikey);

/**
 * @brief Get a public key from secure storage.
 * @details @b #include <security/security_api.h>
 * @param[in] hnd The ID which uniquely accesses security resource
 * @param[in] algo Key algorithm.
 * @param[in] key_name Key name in secure storage.
 * @param[out] pubkey_x Public key will be returned.
 * @param[out] pubkey_y Public key will be returned.
 * @return On success, SECURITY_OK (i.e., 0) is returned. On failure, non-zero value is returned.
 *
 * @since TizenRT v2.1
 */
security_error keymgr_get_key(security_handle hnd, security_key_type algo, const char *key_name, security_data *pubkey_x, security_data *pubkey_y);

/**
 * @brief Remove a key from secure storage.
 * @details @b #include <security/security_api.h>
 * @param[in] hnd The ID which uniquely accesses security resource
 * @param[in] algo Key algorithm.
 * @param[in] key_name Key name in secure storage.
 * @return On success, SECURITY_OK (i.e., 0) is returned. On failure, non-zero value is returned.
 *
 * @since TizenRT v2.1
 */
security_error keymgr_remove_key(security_handle hnd, security_key_type algo, const char *key_name);

#endif // _SECURITY_API_KEYMGR_H__
/**
 * @}
 */

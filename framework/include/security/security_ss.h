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
 * @file security/security_ss.h
 * @brief Provides secure storage APIs for Security
 */
#ifndef _SECURITY_API_SS_H__
#define _SECURITY_API_SS_H__

#include "security_common.h"

/**
 * @brief File information in secure storage
 */
typedef struct security_storage_file {
	char name[20];
	unsigned int attr;
} security_storage_file;

/**
 * @brief File list of secure storage
 */
typedef security_storage_file *security_storage_list;

/**
 * @brief Read a file from secure storage.
 * @details @b #include <security/security_api.h>
 * @param[in] hnd The ID which uniquely accesses security resource
 * @param[in] name File name in secure storage
 * @param[in] offset File offset
 * @param[out] data File data will be returned from secure storage.
 * @return On success, SECURITY_OK (i.e., 0) is returned. On failure, non-zero value is returned.
 *
 * @since TizenRT v2.1
 */
security_error ss_read_secure_storage(security_handle hnd, const char *name, unsigned int offset, security_data *data);

/**
 * @brief Write a file into secure storage.
 * @details @b #include <security/security_api.h>
 * @param[in] hnd The ID which uniquely accesses security resource
 * @param[in] name File name in secure storage.
 * @param[in] offset File offset.
 * @param[in] data File data.
 * @return On success, SECURITY_OK (i.e., 0) is returned. On failure, non-zero value is returned.
 *
 * @since TizenRT v2.1
 */
security_error ss_write_secure_storage(security_handle hnd, const char *name, unsigned int offset, security_data *data);

/**
 * @brief Delete a file from secure storage.
 * @details @b #include <security/security_api.h>
 * @param[in] hnd The ID which uniquely accesses security resource
 * @param[in] name File name in secure storage.
 * @return On success, SECURITY_OK (i.e., 0) is returned. On failure, non-zero value is returned.
 *
 * @since TizenRT v2.1
 */
security_error ss_delete_secure_storage(security_handle hnd, const char *name);

/**
 * @brief Get size of a file from Secure Storage.
 * @details @b #include <security/security_api.h>
 * @param[in] hnd The ID which uniquely accesses security resource.
 * @param[in] name File name.
 * @param[in] size File size will be returned.
 * @return On success, SECURITY_OK (i.e., 0) is returned. On failure, non-zero value is returned.
 *
 * @since TizenRT v2.1
 */
security_error ss_get_size_secure_storage(security_handle hnd, const char *name, unsigned int *size);

/**
 * @brief List all files from both SE Storage and TEE Storage.
 * @details @b #include <security/security_api.h>
 * @param[in] hnd The ID which uniquely accesses security resource
 * @param[out] list File list includes name and type information
 * @return On success, SECURITY_OK (i.e., 0) is returned. On failure, non-zero value is returned.
 *
 * @since TizenRT v2.1
 */
security_error ss_get_list_secure_storage(security_handle hnd, security_storage_list *list);

#endif // _SECURITY_API_SS_H__
/**
 * @}
 */


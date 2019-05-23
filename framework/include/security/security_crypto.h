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
 * @file security/security_crypto.h
 * @brief Provides cryptography APIs for Security
 */
#ifndef _SECURITY_API_CRYPTO_H__
#define _SECURITY_API_CRYPTO_H__

#include "security_common.h"

/**
 * @brief Encrypt input data using an AES key located in secure storage.
 * @details @b #include <security/security_api.h>
 * @param[in] hnd The ID which uniquely accesses security resource
 * @param[in] param Parameters that contains AES encryption mode and IV.
 * @param[in] key_name AES Key name in secure storage.
 * @param[in] input Input data.
 * @param[out] output Encrypted data will be returned
 * @return On success, SECURITY_OK (i.e., 0) is returned. On failure, non-zero value is returned.
 *
 * @since TizenRT v2.1
 */
security_error crypto_aes_encryption(security_handle hnd, security_aes_param *param, const char *key_name, security_data *input, security_data *output);

/**
 * @brief Decrypt the encrypted data using an AES key.
 * @details @b #include <security/security_api.h>
 * @param[in] hnd The ID which uniquely accesses security resource
 * @param[in] param Parameters that contains AES encryption mode and IV.
 * @param[in] key_name AES Key name in secure storage.
 * @param[in] input Encrypted data.
 * @param[out] output Decrypted data will be return.
 * @return On success, SECURITY_OK (i.e., 0) is returned. On failure, non-zero value is returned.
 *
 * @since TizenRT v2.1
 */
security_error crypto_aes_decryption(security_handle hnd, security_aes_param *param, const char *key_name, security_data *input, security_data *output);

/**
 * @brief Encrypt input data using an RSA Key from secure storage.
 * @details @b #include <security/security_api.h>
 * @param[in] hnd The ID which uniquely accesses security resource.
 * @param[in] param RSA parameters.
 * @param[in] key_name RSA key name for encryption.
 * @param[in] input Input data which a user enter.
 * @param[out] output Encrypted data will be returned.
 * @return On success, SECURITY_OK (i.e., 0) is returned. On failure, non-zero value is returned.
 *
 * @since TizenRT v2.1
 */
security_error crypto_rsa_encryption(security_handle hnd, security_rsa_param *param, const char *key_name, security_data *input, security_data *output);

/**
 * @brief Decrypt input data using an RSA Key from secure storage.
 * @details @b #include <security/security_api.h>
 * @param[in] hnd The ID which uniquely accesses security resource
 * @param[in] param RSA parameters
 * @param[in] key_name RSA key name in secure storage.
 * @param[in] input Encrypted data.
 * @param[out] output Decrypted data will be returned.
 * @return On success, SECURITY_OK (i.e., 0) is returned. On failure, non-zero value is returned.
 *
 * @since TizenRT v2.1
 */
security_error crypto_rsa_decryption(security_handle hnd, security_rsa_param *param, const char *key_name, security_data *input, security_data *output);

#endif // _SECURITY_API_CRYPTO_H__
/**
 * @}
 */

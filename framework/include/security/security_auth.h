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
 * @file security/security_auth.h
 * @brief Provides Authenticate APIs for Security
 */
#ifndef _SECURITY_API_AUTH_H__
#define _SECURITY_API_AUTH_H__

#include "security_common.h"

/**
 * Authenticate
 */
/**
 * @brief Generate random variable
 * @details @b #include <security/security_api.h>
 * @param[in] hnd The ID which uniquely accesses security resource
 * @param[in] size Size of the random number.
 * @param[out] random Random number will be returned.
 * @return On success, SECURITY_OK (i.e., 0) is returned. On failure, non-zero value is returned.
 *
 * @since TizenRT v2.1
 */
security_error auth_generate_random(security_handle hnd, unsigned int size, security_data *random);

/**
 * @brief Generate a certificate and store the generated certificate in secure storage.
 * @details @b #include <security/security_api.h>
 * @param[in] hnd The ID which uniquely accesses security resource
 * @param[in] cert_name Certificate name in secure storage.
 * @param[in] csr Certificate Signing Request is filled by user.
 * @param[in] cert Generated certificate will be returned.
 * @return On success, SECURITY_OK (i.e., 0) is returned. On failure, non-zero value is returned.

 * @since TizenRT v2.1
 */
security_error auth_generate_certificate(security_handle hnd, const char *cert_name, security_csr *csr, security_data *cert);

/**
 * @brief Store a certificate in secure storage.
 * @details @b #include <security/security_api.h>
 * @param[in] hnd The ID which uniquely accesses security resource
 * @param[in] cert_name Certificate name in secure storage.
 * @param[in] cert Certificate data which a user enter.
 * @return On success, SECURITY_OK (i.e., 0) is returned. On failure, non-zero value is returned.
 *
 * @since TizenRT v2.1
 */
security_error auth_set_certificate(security_handle hnd, const char *cert_name, security_data *cert);

/**
 * @brief Get a certificate from secure storage.
 * @details @b #include <security/security_api.h>
 * @param[in] hnd The ID which uniquely accesses security resource
 * @param[in] cert_name Certificate name in secure storage.
 * @param[in] cert Certificate in secure storage will be returned.
 * @return On success, SECURITY_OK (i.e., 0) is returned. On failure, non-zero value is returned.
 *
 * @since TizenRT v2.1
 */
security_error auth_get_certificate(security_handle hnd, const char *cert_name, security_data *cert);

/**
 * @brief Remove a certificate in secure storage.
 * @details @b #include <security/security_api.h>
 * @param[in] hnd The ID which uniquely accesses security resource
 * @param[in] cert_name Certificate name in Secure storage.
 * @return On success, SECURITY_OK (i.e., 0) is returned. On failure, non-zero value is returned.
 *
 * @since TizenRT v2.1
 */
security_error auth_remove_certificate(security_handle hnd, const char *cert_name);

/**
 * @brief Get a signed data by RSA Private Key from hashed data.
 * @details @b #include <security/security_api.h>
 * @param[in] hnd The ID which uniquely accesses security resource
 * @param[in] param Addtional information to get a RSA signature
 * @param[in] key_name Key name for signing
 * @param[in] hash Hashed data.
 * @param[out] sign Signed data from hashed data will be return.
 * @return On success, SECURITY_OK (i.e., 0) is returned. On failure, non-zero value is returned.
 *
 * @since TizenRT v2.1
 */
security_error auth_get_rsa_signature(security_handle hnd, security_rsa_param *param, const char *key_name, security_data *hash, security_data *sign);

/**
 * @brief Verify signed data with the original hashed data.
 * @details @b #include <security/security_api.h>
 * @param[in] hnd The ID which uniquely accesses security resource
 * @param[in] param Addtional information to verify a RSA signature
 * @param[in] key_name Key name for verifing
 * @param[in] hash Hashed data
 * @param[in] sign Signed data from hashed data
 * @return On success, SECURITY_OK (i.e., 0) is returned. On failure, non-zero value is returned.
 *
 * @since TizenRT v2.1
 */
security_error auth_verify_rsa_signature(security_handle hnd, security_rsa_param *param, const char *key_name, security_data *hash, security_data *sign);

/**
 * @brief Get signed data by ECDSA key from hashed data.
 * @details @b #include <security/security_api.h>
 * @param[in] hnd The ID which uniquely accesses security resource
 * @param[in] param Additional information to get ECDSA signature
 * @param[in] key_name Key name for signing.
 * @param[in] hash Hashed data
 * @param[out] sign Signed data from hashed data will be returned.
 * @return On success, SECURITY_OK (i.e., 0) is returned. On failure, non-zero value is returned.
 *
 * @since TizenRT v2.1
 */
security_error auth_get_ecdsa_signature(security_handle hnd, security_ecdsa_param *param, const char *key_name, security_data *hash, security_data *sign);

/**
 * @brief Verify signed data using ECDSA Key with the original hashed data.
 * @details @b #include <security/security_api.h>
 * @param[in] hnd The ID which uniquely accesses security resource.
 * @param[in] param Additional information to get ECDSA signature.
 * @param[in] key_name Key name for signing.
 * @param[in] hash Hashed data.
 * @param[in] sign Signed data from hashed data.
 * @return On success, SECURITY_OK (i.e., 0) is returned. On failure, non-zero value is returned.
 *
 * @since TizenRT v2.1
 */
security_error auth_verify_ecdsa_signature(security_handle hnd, security_ecdsa_param *param, const char *key_name, security_data *hash, security_data *sign);

/**
 * @brief Get hashed data from input data.
 * @details @b #include <security/security_api.h>
 * @param[in] hnd The ID which uniquely accesses security resource
 * @param[in] mode Hash algorithm
 * @param[in] data Input data
 * @param[out] hash Hashed data
 * @return On success, SECURITY_OK (i.e., 0) is returned. On failure, non-zero value is returned.
 *
 * @since TizenRT v2.1
 */
security_error auth_get_hash(security_handle hnd, security_hash_mode mode, security_data *data, security_data *hash);

/**
 * @brief Get HMAC from input data
 * @details @b #include <security/security_api.h>
 * @param[in] hnd The ID which uniquely accesses security resource
 * @param[in] mode HMAC algorithm
 * @param[in] key_name HMAC key name in secure storage
 * @param[in] data Input data
 * @param[out] hmac HMAC data
 * @return On success, SECURITY_OK (i.e., 0) is returned. On failure, non-zero value is returned.
 *
 * @since TizenRT v2.1
 */
security_error auth_get_hmac(security_handle hnd, security_hmac_mode mode, const char *key_name, security_data *data, security_data *hmac);

/**
 * @brief Generate DH Parameters and Get Public
 * @details @b #include <security/security_api.h>
 * @param[in] hnd The ID which uniquely accesses security resource
 * @param[in] dh_name Storage name for storing data
 * @param[out] param DH parameters will be returned
 * @return On success, SECURITY_OK (i.e., 0) is returned. On failure, non-zero value is returned.
 *
 * @since TizenRT v2.1
 */
security_error auth_generate_dhparams(security_handle hnd, const char *dh_name, security_dh_param *param);

/**
 * @brief Compute DH Parameters and Get Premaster Secret
 * @details @b #include <security/security_api.h>
 * @param[in] hnd The ID which uniquely accesses security resource
 * @param[in] dh_name Storage anme for storing data
 * @param[in] param DH Parameters
 * @param[out] Premaster secret will be return.
 * @return On success, SECURITY_OK (i.e., 0) is returned. On failure, non-zero value is returned.
 *
 * @since TizenRT v2.1
 */
security_error auth_compute_dhparams(security_handle hnd, const char *dh_name, security_dh_param *param, security_data *secret);

/**
 * @brief Generate ECDH Key Pair and Get Public Key
 * @details @b #include <security/security_api.h>
 * @param[in] hnd The ID which uniquely accesses security resource
 * @param[in] ecdh_name ECDH name in secure storage
 * @param[in] param ECC parameters
 * @return On success, SECURITY_OK (i.e., 0) is returned. On failure, non-zero value is returned.
 *
 * @since TizenRT v2.1
 */
security_error auth_generate_ecdhkey(security_handle hnd, const char *ecdh_name, security_ecdh_param *param);

/**
 * @brief Compute ECDH Key Pair and Get Pre Master Secret
 * @details @b #include <security/security_api.h>
 * @param[in] hnd The ID which uniquely accesses security resource
 * @param[in] ecdh_name ECDH name in secure storage
 * @param[in] param ECC parameters
 * @param[in] secret Premaster Secret will be returned.
 * @return On success, SECURITY_OK (i.e., 0) is returned. On failure, non-zero value is returned.
 *
 * @since TizenRT v2.1
 */
security_error auth_compute_ecdhkey(security_handle hnd, const char *ecdh_name, security_ecdh_param *param, security_data *secret);

#endif //  _SECURITY_API_AUTH_H__
/**
 * @}
 */

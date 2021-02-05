/****************************************************************************
 *
 * Copyright 2020 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include <tinyara/config.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <tinyara/seclink.h>
#include <tinyara/seclink_drv.h>
#include <stress_tool/st_perf.h>
#include "sl_test.h"

/*
 * Key
 * Injected key slot range 0~31
 * tp1x: 0~7
 * RAM key slot range 32~63
 * tp1x: 32~63
 */
#define RO_SLOT_SIZE 32
#define RO_VALID_RANGE 8
#define RW_SLOT_SIZE 32
#define RW_VALID_RANGE 32

#define SL_TEST_KEY_MEM_SIZE 1024
#define SL_TEST_KEY_TRIAL 1
#define SL_TEST_KEY_LIMIT_TIME 1000000

// ToDo: key length will be fixed. it doesn't consider real key size.
#define SL_TEST_SYMKEY_LEN 32
#define SL_TEST_PUBKEY_LEN 32
#define SL_TEST_PRIKEY_LEN 32

static sl_ctx g_hnd;

static int g_ro_slot_index[RO_SLOT_SIZE] = {0,};
static int g_ro_expect[RO_SLOT_SIZE] = {0,};

static int g_rw_slot_index[RW_SLOT_SIZE] = {0,};
static int g_rw_expect[RW_SLOT_SIZE] = {0,};

static hal_data g_aes_key_in;
static hal_data g_aes_key_out;

static hal_data g_pubkey_in;
static hal_data g_pubkey_out;

static hal_data g_prikey_in;
static hal_data g_prikey_out;

static const unsigned char EC_Private_Key[] =
{
	0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x32, 0x0d, 0x45, 0x48, 0x4b,
	0x72, 0xea, 0x5b, 0x2b, 0x1e, 0xf0, 0x8c, 0x22, 0xd4, 0xe3, 0x6d, 0xe9,
	0x22, 0xc3, 0x29, 0x29, 0xe0, 0x63, 0xe4, 0x0c, 0x50, 0xf6, 0xc7, 0x5c,
	0xd4, 0xb8, 0xe5, 0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
	0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x55, 0xe7, 0x65,
	0x38, 0x27, 0x5b, 0x58, 0xfd, 0x90, 0x46, 0x86, 0x6b, 0xcd, 0xf9, 0x40,
	0xd7, 0x74, 0xd0, 0x8b, 0x82, 0x3f, 0x82, 0xb9, 0xf4, 0x89, 0x14, 0xd3,
	0x56, 0xf6, 0x49, 0x9a, 0x3c, 0x9b, 0xe5, 0x3c, 0xb1, 0xd4, 0x5e, 0xe6,
	0xa8, 0x42, 0x60, 0xda, 0x37, 0x45, 0xc8, 0xd7, 0xed, 0xa1, 0xa1, 0x02,
	0x6c, 0xf5, 0x1d, 0x35, 0x04, 0x60, 0xaa, 0x1d, 0x72, 0xe2, 0x88, 0xcf,
	0x28, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07
};

static const unsigned char EC_Public_Key_Pair[] =
{
	0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
	0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x55, 0xe7, 0x65, 0x38, 0x27,
	0x5b, 0x58, 0xfd, 0x90, 0x46, 0x86, 0x6b, 0xcd, 0xf9, 0x40, 0xd7, 0x74, 0xd0, 0x8b, 0x82, 0x3f,
	0x82, 0xb9, 0xf4, 0x89, 0x14, 0xd3, 0x56, 0xf6, 0x49, 0x9a, 0x3c, 0x9b, 0xe5, 0x3c, 0xb1, 0xd4,
	0x5e, 0xe6, 0xa8, 0x42, 0x60, 0xda, 0x37, 0x45, 0xc8, 0xd7, 0xed, 0xa1, 0xa1, 0x02, 0x6c, 0xf5,
	0x1d, 0x35, 0x04, 0x60, 0xaa, 0x1d, 0x72, 0xe2, 0x88, 0xcf, 0x28
};

static void _sl_init_keytest(void)
{
	for (int i = 0; i < RO_SLOT_SIZE; ++i) {
		g_ro_slot_index[i] = i;
		if (i < RO_VALID_RANGE) {
			g_ro_expect[i] = HAL_SUCCESS;
		} else {
			g_ro_expect[i] = HAL_FAIL;
		}
	}

	for (int i = 0; i < RW_SLOT_SIZE; ++i) {
		g_rw_slot_index[i] = i + RO_SLOT_SIZE;
		if (i < RW_VALID_RANGE) {
			g_rw_expect[i] = HAL_SUCCESS;
		} else {
			g_rw_expect[i] = HAL_INVALID_SLOT_RANGE;
		}
	}

	/*  Symmetric key */
	int res = sl_test_malloc_buffer(&g_aes_key_in, SL_TEST_SYMKEY_LEN);
	if (res < 0) {
		SL_TEST_ERR("memory alloc error");
		return;
	}
	g_aes_key_in.data_len = SL_TEST_SYMKEY_LEN;
	memset(g_aes_key_in.data, 0xa5, SL_TEST_SYMKEY_LEN);

	res = sl_test_malloc_buffer(&g_aes_key_out, SL_TEST_KEY_MEM_SIZE);
	if (res < 0) {
		SL_TEST_ERR("memory alloc error");
		return;
	}

	/*  public key */
	//res = sl_test_malloc_buffer(&g_pubkey_in, SL_TEST_PUBKEY_LEN);
	//if (res < 0) {
	//	SL_TEST_ERR("memory alloc error");
	//	return;
	//}
	//g_pubkey_in.data_len = SL_TEST_PUBKEY_LEN;
	//memset(g_pubkey_in.data, 0xa5, SL_TEST_PUBKEY_LEN);
	g_pubkey_in.data = EC_Public_Key_Pair;
	g_pubkey_in.data_len = sizeof(EC_Public_Key_Pair);

	res = sl_test_malloc_buffer(&g_pubkey_out, SL_TEST_PUBKEY_LEN);
	if (res < 0) {
		SL_TEST_ERR("memory alloc error");
		return;
	}
	g_pubkey_out.data_len = SL_TEST_PUBKEY_LEN;

	/*  Private key */
	//res = sl_test_malloc_buffer(&g_prikey_in, SL_TEST_PRIKEY_LEN);
	//if (res < 0) {
	//	SL_TEST_ERR("memory alloc error");
	//	return;
	//}
	//g_prikey_in.data_len = SL_TEST_PRIKEY_LEN;
	//memset(g_prikey_in.data, 0xa6, SL_TEST_PRIKEY_LEN);
	g_prikey_in.data = (void *)EC_Private_Key;
	g_prikey_in.data_len = sizeof(EC_Private_Key);

	res = sl_test_malloc_buffer(&g_prikey_out, SL_TEST_PRIKEY_LEN);
	if (res < 0) {
		SL_TEST_ERR("memory alloc error");
		return;
	}
	g_prikey_out.data_len = SL_TEST_PRIKEY_LEN;

	res = sl_init(&g_hnd);
	if (res != SECLINK_OK) {
		printf("initialize error\n");
	}
}

static void _sl_deinit_keytest(void)
{
	sl_test_free_buffer(&g_aes_key_in);
	sl_test_free_buffer(&g_aes_key_out);

	//sl_test_free_buffer(&g_pubkey_in);
	sl_test_free_buffer(&g_pubkey_out);

	//sl_test_free_buffer(&g_prikey_in);
	sl_test_free_buffer(&g_prikey_out);

	int res = sl_deinit(g_hnd);
	if (res != SECLINK_OK) {
		printf("deinitialize error\n");
	}
}

/**
 * Description: Set symmetric key in RO area
 */
TEST_F(set_sym_key_ro)
{
	ST_START_TEST;

	for (int i = 0; i < RO_SLOT_SIZE; ++i) {
		hal_result_e hres = HAL_FAIL;
		ST_EXPECT_EQ(SECLINK_OK, sl_set_key(g_hnd, HAL_KEY_AES_256, g_ro_slot_index[i], &g_aes_key_in, NULL, &hres));
		ST_EXPECT_EQ(HAL_INVALID_REQUEST, hres);
	}

	ST_END_TEST;
}

/**
 * Description: Get symmetric key in RO area
 */
TEST_F(get_sym_key_ro)
{
	ST_START_TEST;

	// the result depends on what key type is stored in RO area. so modify return type latter
	for (int i = 0; i < RO_VALID_RANGE; ++i) {
		hal_result_e hres = HAL_FAIL;
		ST_EXPECT_EQ(SECLINK_OK, sl_get_key(g_hnd, HAL_KEY_AES_256, g_ro_slot_index[i], &g_aes_key_out, &hres));
		ST_EXPECT_EQ(HAL_INVALID_REQUEST, hres);
	}

	for (int i = RO_VALID_RANGE; i < RO_SLOT_SIZE; ++i) {
		hal_result_e hres = HAL_FAIL;
		ST_EXPECT_EQ(SECLINK_OK, sl_get_key(g_hnd, HAL_KEY_AES_256, g_ro_slot_index[i], &g_aes_key_out, &hres));
		ST_EXPECT_EQ(HAL_INVALID_SLOT_RANGE, hres);
	}

	ST_END_TEST;
}

/**
 * Description: Remove symmetric key in RO area
 */
TEST_F(remove_sym_key_ro)
{
	ST_START_TEST;

	for (int i = 0; i < RO_SLOT_SIZE; ++i) {
		hal_result_e hres = HAL_FAIL;
		ST_EXPECT_EQ(SECLINK_OK, sl_remove_key(g_hnd, HAL_KEY_AES_256, g_ro_slot_index[i], &hres));
		ST_EXPECT_EQ(HAL_INVALID_REQUEST, hres);
	}

	ST_END_TEST;
}

/**
 * Description: Generate a symmetric key in RO area
 */
TEST_F(generate_sym_key_ro)
{
	ST_START_TEST;

	for (int i = 0; i < RO_SLOT_SIZE; ++i) {
		hal_result_e hres = HAL_FAIL;
		ST_EXPECT_EQ(SECLINK_OK, sl_generate_key(g_hnd, HAL_KEY_AES_256, g_ro_slot_index[i], &hres));
		ST_EXPECT_EQ(HAL_INVALID_REQUEST, hres);
	}

	ST_END_TEST;
}

/**
 * Description: Set public key in RO area
 */
TEST_F(set_public_key_ro)
{
	ST_START_TEST;

	for (int i = 0; i < RO_SLOT_SIZE; ++i) {
		hal_result_e hres = HAL_FAIL;
		ST_EXPECT_EQ(SECLINK_OK, sl_set_key(g_hnd, HAL_KEY_ECC_SEC_P256R1, g_ro_slot_index[i], &g_pubkey_in, NULL, &hres));
		ST_EXPECT_EQ(HAL_INVALID_REQUEST, hres);
	}

	ST_END_TEST;
}

/**
 * Description: Get public key in RO area
 */
TEST_F(get_public_key_ro)
{
	ST_START_TEST;

	// the result depends on what key type is stored in RO area. so modify return type latter
	for (int i = 0; i < RO_VALID_RANGE; ++i) {
		hal_result_e hres = HAL_FAIL;
		ST_EXPECT_EQ(SECLINK_OK, sl_get_key(g_hnd, HAL_KEY_ECC_SEC_P256R1, g_ro_slot_index[i], &g_pubkey_out, &hres));
		ST_EXPECT_EQ(HAL_INVALID_REQUEST, hres);
	}

	for (int i = RO_VALID_RANGE; i < RO_SLOT_SIZE; ++i) {
		hal_result_e hres = HAL_FAIL;
		ST_EXPECT_EQ(SECLINK_OK, sl_get_key(g_hnd, HAL_KEY_ECC_SEC_P256R1, g_ro_slot_index[i], &g_pubkey_out, &hres));
		ST_EXPECT_EQ(HAL_INVALID_SLOT_RANGE, hres);
	}

	ST_END_TEST;
}

/**
 * Description: Remove public key in RO area
 */
TEST_F(remove_public_key_ro)
{
	ST_START_TEST;

	for (int i = 0; i < RO_SLOT_SIZE; ++i) {
		hal_result_e hres = HAL_FAIL;
		ST_EXPECT_EQ(SECLINK_OK, sl_remove_key(g_hnd, HAL_KEY_ECC_SEC_P256R1, g_ro_slot_index[i], &hres));
		ST_EXPECT_EQ(HAL_INVALID_REQUEST, hres);
	}

	ST_END_TEST;
}

/**
 * Description: Generate a public key in RO area
 */

TEST_F(generate_public_key_ro)
{
	ST_START_TEST;

	for (int i = 0; i < RO_SLOT_SIZE; ++i) {
		hal_result_e hres = HAL_FAIL;
		ST_EXPECT_EQ(SECLINK_OK, sl_generate_key(g_hnd, HAL_KEY_ECC_SEC_P256R1, g_ro_slot_index[i], &hres));
		ST_EXPECT_EQ(HAL_INVALID_REQUEST, hres);
	}

	ST_END_TEST;
}

/**
 * Description: Set a private key in RO area
 */

TEST_F(set_private_key_ro)
{
	ST_START_TEST;

	for (int i = 0; i < RO_SLOT_SIZE; ++i) {
		hal_result_e hres = HAL_FAIL;
		ST_EXPECT_EQ(SECLINK_OK, sl_set_key(g_hnd, HAL_KEY_ECC_SEC_P256R1, g_ro_slot_index[i], NULL, &g_prikey_in, &hres));
		ST_EXPECT_EQ(HAL_INVALID_REQUEST, hres);
	}

	ST_END_TEST;
}

/**
 * Description: Get a private key in RO area
 */
TEST_F(get_private_key_ro)
{
	ST_START_TEST;

	// the result depends on what key type is stored in RO area. so modify return type latter
	for (int i = 0; i < RO_VALID_RANGE; ++i) {
		hal_result_e hres = HAL_FAIL;
		ST_EXPECT_EQ(SECLINK_OK, sl_get_key(g_hnd, HAL_KEY_ECC_SEC_P256R1, g_ro_slot_index[i], &g_prikey_out, &hres));
		ST_EXPECT_EQ(HAL_INVALID_REQUEST, hres);
	}

	for (int i = RO_VALID_RANGE; i < RO_SLOT_SIZE; ++i) {
		hal_result_e hres = HAL_FAIL;
		ST_EXPECT_EQ(SECLINK_OK, sl_get_key(g_hnd, HAL_KEY_ECC_SEC_P256R1, g_ro_slot_index[i], &g_prikey_out, &hres));
		ST_EXPECT_EQ(HAL_INVALID_SLOT_RANGE, hres);
	}

	ST_END_TEST;
}

/**
 * Description: Removt a private key in RO area
 */
TEST_F(remove_private_key_ro)
{
	ST_START_TEST;

	for (int i = 0; i < RO_SLOT_SIZE; ++i) {
		hal_result_e hres = HAL_FAIL;
		ST_EXPECT_EQ(SECLINK_OK, sl_remove_key(g_hnd, HAL_KEY_ECC_SEC_P256R1, g_ro_slot_index[i], &hres));
		ST_EXPECT_EQ(HAL_INVALID_REQUEST, hres);
	}

	ST_END_TEST;
}

/**
 * Description: Generate t a private key in RO area
 */

TEST_F(generate_private_key_ro)
{
	ST_START_TEST;

	for (int i = 0; i < RO_SLOT_SIZE; ++i) {
		hal_result_e hres = HAL_FAIL;
		ST_EXPECT_EQ(SECLINK_OK, sl_generate_key(g_hnd, HAL_KEY_ECC_SEC_P256R1, g_ro_slot_index[i], &hres));
		ST_EXPECT_EQ(HAL_INVALID_REQUEST, hres);
	}

	ST_END_TEST;
}

/**
 * Description: Set a symmetric key in RW area
 */
TEST_SETUP(set_sym_key_rw)
{
	ST_START_TEST;
	ST_END_TEST;
}

TEST_TEARDOWN(set_sym_key_rw)
{
	ST_START_TEST;

	for (int i = 0; i < RW_SLOT_SIZE; ++i) {
		hal_result_e hres = HAL_FAIL;
		ST_EXPECT_EQ(SECLINK_OK, sl_remove_key(g_hnd, HAL_KEY_AES_256, g_rw_slot_index[i], &hres));
		ST_EXPECT_EQ(g_rw_expect[i], hres);
	}

	ST_END_TEST;
}

TEST_F(set_sym_key_rw)
{
	ST_START_TEST;

	for (int i = 0; i < RW_SLOT_SIZE; ++i) {
		hal_result_e hres = HAL_FAIL;
		ST_EXPECT_EQ(SECLINK_OK, sl_set_key(g_hnd, HAL_KEY_AES_256, g_rw_slot_index[i], &g_aes_key_in, NULL, &hres));
		ST_EXPECT_EQ(g_rw_expect[i], hres);
	}

	ST_END_TEST;
}

/**
 * Description: Get a symmetric key in RW area
 */
TEST_SETUP(get_sym_key_rw)
{
	ST_START_TEST;
	for (int i = 0; i < RW_SLOT_SIZE; ++i) {
		hal_result_e hres = HAL_FAIL;
		ST_EXPECT_EQ(SECLINK_OK, sl_set_key(g_hnd, HAL_KEY_AES_256, g_rw_slot_index[i], &g_aes_key_in, NULL, &hres));
		ST_EXPECT_EQ(g_rw_expect[i], hres);
	}
	ST_END_TEST;
}

TEST_TEARDOWN(get_sym_key_rw)
{
	ST_START_TEST;
	for (int i = 0; i < RW_SLOT_SIZE; ++i) {
		hal_result_e hres = HAL_FAIL;
		ST_EXPECT_EQ(SECLINK_OK, sl_remove_key(g_hnd, HAL_KEY_AES_256, g_rw_slot_index[i], &hres));
		ST_EXPECT_EQ(g_rw_expect[i], hres);
	}

	ST_END_TEST;
}

TEST_F(get_sym_key_rw)
{
	ST_START_TEST;
	// it's symmetric key, so API should not return key value.
	for (int i = 0; i < RW_SLOT_SIZE; ++i) {
		hal_result_e hres = HAL_FAIL;
		ST_EXPECT_EQ(SECLINK_OK, sl_get_key(g_hnd, HAL_KEY_AES_256, g_rw_slot_index[i], &g_aes_key_out, &hres));
		ST_EXPECT_EQ(HAL_INVALID_REQUEST, hres);
	}
	ST_END_TEST;
}

/**
 * Description: Remove a symmetric key in RW area
 */
TEST_SETUP(remove_sym_key_rw)
{
	ST_START_TEST;
	for (int i = 0; i < RW_SLOT_SIZE; ++i) {
		hal_result_e hres = HAL_FAIL;
		ST_EXPECT_EQ(SECLINK_OK, sl_set_key(g_hnd, HAL_KEY_AES_256, g_rw_slot_index[i], &g_aes_key_in, NULL, &hres));
		ST_EXPECT_EQ(g_rw_expect[i], hres);
	}
	ST_END_TEST;
}

TEST_TEARDOWN(remove_sym_key_rw)
{
	ST_START_TEST;
	ST_END_TEST;
}

TEST_F(remove_sym_key_rw)
{
	ST_START_TEST;
	for (int i = 0; i < RW_SLOT_SIZE; ++i) {
		hal_result_e hres = HAL_FAIL;
		ST_EXPECT_EQ(SECLINK_OK, sl_remove_key(g_hnd, HAL_KEY_AES_256, g_rw_slot_index[i], &hres));
		ST_EXPECT_EQ(g_rw_expect[i], hres);
	}
	ST_END_TEST;
}

/**
 * Description: Generate a symmetric key in RW area
 */
TEST_SETUP(generate_sym_key_rw)
{
	ST_START_TEST;
	ST_END_TEST;
}

TEST_TEARDOWN(generate_sym_key_rw)
{
	ST_START_TEST;
	for (int i = 0; i < RW_SLOT_SIZE; ++i) {
		hal_result_e hres = HAL_FAIL;
		ST_EXPECT_EQ(SECLINK_OK, sl_remove_key(g_hnd, HAL_KEY_AES_256, g_rw_slot_index[i], &hres));
		ST_EXPECT_EQ(g_rw_expect[i], hres);
	}
	ST_END_TEST;
}

TEST_F(generate_sym_key_rw)
{
	ST_START_TEST;
	for (int i = 0; i < RW_SLOT_SIZE; ++i) {
		hal_result_e hres = HAL_FAIL;
		ST_EXPECT_EQ(SECLINK_OK, sl_generate_key(g_hnd, HAL_KEY_AES_256, g_rw_slot_index[i], &hres));
		ST_EXPECT_EQ(g_rw_expect[i], hres);
	}
	ST_END_TEST;
}

/**
 * Description: Set a public key in RW area
 */
TEST_SETUP(set_public_key_rw)
{
	ST_START_TEST;
	ST_END_TEST;
}

TEST_TEARDOWN(set_public_key_rw)
{
	ST_START_TEST;

	for (int i = 0; i < RW_SLOT_SIZE; ++i) {
		hal_result_e hres = HAL_FAIL;
		ST_EXPECT_EQ(SECLINK_OK, sl_remove_key(g_hnd, HAL_KEY_ECC_SEC_P256R1, g_rw_slot_index[i], &hres));
		ST_EXPECT_EQ(g_rw_expect[i], hres);
	}

	ST_END_TEST;
}

TEST_F(set_public_key_rw)
{
	ST_START_TEST;

	for (int i = 0; i < RW_SLOT_SIZE; ++i) {
		hal_result_e hres = HAL_FAIL;
		ST_EXPECT_EQ(SECLINK_OK, sl_set_key(g_hnd, HAL_KEY_ECC_SEC_P256R1, g_rw_slot_index[i], &g_pubkey_in, NULL, &hres));
		ST_EXPECT_EQ(g_rw_expect[i], hres);
	}

	ST_END_TEST;
}

/**
 * Description: Get a public key in RW area
 */
TEST_SETUP(get_public_key_rw)
{
	ST_START_TEST;
	for (int i = 0; i < RW_SLOT_SIZE; ++i) {
		hal_result_e hres = HAL_FAIL;
		ST_EXPECT_EQ(SECLINK_OK, sl_set_key(g_hnd, HAL_KEY_ECC_SEC_P256R1, g_rw_slot_index[i], &g_pubkey_in, NULL, &hres));
		ST_EXPECT_EQ(g_rw_expect[i], hres);
	}
	ST_END_TEST;
}

TEST_TEARDOWN(get_public_key_rw)
{
	ST_START_TEST;
	for (int i = 0; i < RW_SLOT_SIZE; ++i) {
		hal_result_e hres = HAL_FAIL;
		ST_EXPECT_EQ(SECLINK_OK, sl_remove_key(g_hnd, HAL_KEY_ECC_SEC_P256R1, g_rw_slot_index[i], &hres));
		ST_EXPECT_EQ(g_rw_expect[i], hres);
	}

	ST_END_TEST;
}

TEST_F(get_public_key_rw)
{
	ST_START_TEST;
	// it's symmetric key, so API should not return key value.
	for (int i = 0; i < RW_SLOT_SIZE; ++i) {
		hal_result_e hres = HAL_FAIL;
		ST_EXPECT_EQ(SECLINK_OK, sl_get_key(g_hnd, HAL_KEY_ECC_SEC_P256R1, g_rw_slot_index[i], &g_pubkey_out, &hres));
		ST_EXPECT_EQ(g_rw_expect[i], hres);
	}
	ST_END_TEST;
}

/**
 * Description: Remove a public key in RW area
 */
TEST_SETUP(remove_public_key_rw)
{
	ST_START_TEST;
	for (int i = 0; i < RW_SLOT_SIZE; ++i) {
		hal_result_e hres = HAL_FAIL;
		ST_EXPECT_EQ(SECLINK_OK, sl_set_key(g_hnd, HAL_KEY_ECC_SEC_P256R1, g_rw_slot_index[i], &g_pubkey_in, NULL, &hres));
		ST_EXPECT_EQ(g_rw_expect[i], hres);
	}
	ST_END_TEST;
}

TEST_TEARDOWN(remove_public_key_rw)
{
	ST_START_TEST;
	ST_END_TEST;
}

TEST_F(remove_public_key_rw)
{
	ST_START_TEST;
	for (int i = 0; i < RW_SLOT_SIZE; ++i) {
		hal_result_e hres = HAL_FAIL;
		ST_EXPECT_EQ(SECLINK_OK, sl_remove_key(g_hnd, HAL_KEY_ECC_SEC_P256R1, g_rw_slot_index[i], &hres));
		ST_EXPECT_EQ(g_rw_expect[i], hres);
	}
	ST_END_TEST;
}

/**
 * Description: Generate a public key in RW area
 */
TEST_SETUP(generate_public_key_rw)
{
	ST_START_TEST;
	ST_END_TEST;
}

TEST_TEARDOWN(generate_public_key_rw)
{
	ST_START_TEST;
	for (int i = 0; i < RW_SLOT_SIZE; ++i) {
		hal_result_e hres = HAL_FAIL;
		ST_EXPECT_EQ(SECLINK_OK, sl_remove_key(g_hnd, HAL_KEY_ECC_SEC_P256R1, g_rw_slot_index[i], &hres));
		ST_EXPECT_EQ(g_rw_expect[i], hres);
	}
	ST_END_TEST;
}

TEST_F(generate_public_key_rw)
{
	ST_START_TEST;
	for (int i = 0; i < RW_SLOT_SIZE; ++i) {
		hal_result_e hres = HAL_FAIL;
		ST_EXPECT_EQ(SECLINK_OK, sl_generate_key(g_hnd, HAL_KEY_ECC_SEC_P256R1, g_rw_slot_index[i], &hres));
		ST_EXPECT_EQ(g_rw_expect[i], hres);
	}
	ST_END_TEST;
}

/**
 * Description: Set a private key in RW area
 */
TEST_SETUP(set_private_key_rw)
{
	ST_START_TEST;
	ST_END_TEST;
}

TEST_TEARDOWN(set_private_key_rw)
{
	ST_START_TEST;

	for (int i = 0; i < RW_SLOT_SIZE; ++i) {
		hal_result_e hres = HAL_FAIL;
		ST_EXPECT_EQ(SECLINK_OK, sl_remove_key(g_hnd, HAL_KEY_ECC_SEC_P256R1, g_rw_slot_index[i], &hres));
		ST_EXPECT_EQ(g_rw_expect[i], hres);
	}

	ST_END_TEST;
}

TEST_F(set_private_key_rw)
{
	ST_START_TEST;

	for (int i = 0; i < RW_SLOT_SIZE; ++i) {
		hal_result_e hres = HAL_FAIL;
		ST_EXPECT_EQ(SECLINK_OK, sl_set_key(g_hnd, HAL_KEY_ECC_SEC_P256R1, g_rw_slot_index[i], NULL, &g_prikey_in, &hres));
		ST_EXPECT_EQ(g_rw_expect[i], hres);
	}

	ST_END_TEST;
}

/**
 * Description: Get a private key in RW area
 */
TEST_SETUP(get_private_key_rw)
{
	ST_START_TEST;
	for (int i = 0; i < RW_SLOT_SIZE; ++i) {
		hal_result_e hres = HAL_FAIL;
		ST_EXPECT_EQ(SECLINK_OK, sl_set_key(g_hnd, HAL_KEY_ECC_SEC_P256R1, g_rw_slot_index[i], NULL, &g_prikey_in, &hres));
		ST_EXPECT_EQ(g_rw_expect[i], hres);
	}
	ST_END_TEST;
}

TEST_TEARDOWN(get_private_key_rw)
{
	ST_START_TEST;
	for (int i = 0; i < RW_SLOT_SIZE; ++i) {
		hal_result_e hres = HAL_FAIL;
		ST_EXPECT_EQ(SECLINK_OK, sl_remove_key(g_hnd, HAL_KEY_ECC_SEC_P256R1, g_rw_slot_index[i], &hres));
		ST_EXPECT_EQ(g_rw_expect[i], hres);
	}

	ST_END_TEST;
}

TEST_F(get_private_key_rw)
{
	ST_START_TEST;
	// it's symmetric key, so API should not return key value.
	for (int i = 0; i < RW_SLOT_SIZE; ++i) {
		hal_result_e hres = HAL_FAIL;
		ST_EXPECT_EQ(SECLINK_OK, sl_get_key(g_hnd, HAL_KEY_ECC_SEC_P256R1, g_rw_slot_index[i], &g_prikey_out, &hres));
		ST_EXPECT_EQ(g_rw_expect[i], hres);
	}
	ST_END_TEST;
}

/**
 * Description: Remove a private key in RW area
 */
TEST_SETUP(remove_private_key_rw)
{
	ST_START_TEST;
	for (int i = 0; i < RW_SLOT_SIZE; ++i) {
		hal_result_e hres = HAL_FAIL;
		ST_EXPECT_EQ(SECLINK_OK, sl_set_key(g_hnd, HAL_KEY_ECC_SEC_P256R1, g_rw_slot_index[i], NULL, &g_prikey_in, &hres));
		ST_EXPECT_EQ(g_rw_expect[i], hres);
	}
	ST_END_TEST;
}

TEST_TEARDOWN(remove_private_key_rw)
{
	ST_START_TEST;
	ST_END_TEST;
}

TEST_F(remove_private_key_rw)
{
	ST_START_TEST;
	for (int i = 0; i < RW_SLOT_SIZE; ++i) {
		hal_result_e hres = HAL_FAIL;
		ST_EXPECT_EQ(SECLINK_OK, sl_remove_key(g_hnd, HAL_KEY_ECC_SEC_P256R1, g_rw_slot_index[i], &hres));
		ST_EXPECT_EQ(g_rw_expect[i], hres);
	}
	ST_END_TEST;
}

static const unsigned char HA_IOT_Device_Cert[681] =
{
	0x30, 0x82, 0x02, 0xa5, 0x30, 0x82, 0x02, 0x4a, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x48,
	0x41, 0x30, 0x31, 0x54, 0x31, 0x39, 0x30, 0x32, 0x32, 0x35, 0x30, 0x34, 0x30, 0x30, 0x30, 0x30,
	0x30, 0x30, 0x30, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x05,
	0x20, 0x30, 0x81, 0x83, 0x31, 0x38, 0x30, 0x36, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x2f, 0x53,
	0x61, 0x6d, 0x73, 0x75, 0x6e, 0x67, 0x20, 0x45, 0x6c, 0x65, 0x63, 0x74, 0x72, 0x6f, 0x6e, 0x69,
	0x63, 0x73, 0x20, 0x4f, 0x43, 0x46, 0x20, 0x48, 0x41, 0x20, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65,
	0x20, 0x53, 0x75, 0x62, 0x43, 0x41, 0x20, 0x76, 0x31, 0x20, 0x54, 0x45, 0x53, 0x54, 0x31, 0x1c,
	0x30, 0x1a, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x13, 0x4f, 0x43, 0x46, 0x20, 0x48, 0x41, 0x20,
	0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x20, 0x53, 0x75, 0x62, 0x43, 0x41, 0x31, 0x1c, 0x30, 0x1a,
	0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x13, 0x53, 0x61, 0x6d, 0x73, 0x75, 0x6e, 0x67, 0x20, 0x45,
	0x6c, 0x65, 0x63, 0x74, 0x72, 0x6f, 0x6e, 0x69, 0x63, 0x73, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,
	0x55, 0x04, 0x06, 0x13, 0x02, 0x4b, 0x52, 0x30, 0x20, 0x17, 0x0d, 0x31, 0x39, 0x30, 0x32, 0x32,
	0x35, 0x30, 0x32, 0x30, 0x35, 0x31, 0x36, 0x5a, 0x18, 0x0f, 0x32, 0x30, 0x36, 0x39, 0x31, 0x32,
	0x33, 0x31, 0x31, 0x34, 0x35, 0x39, 0x35, 0x39, 0x5a, 0x30, 0x81, 0x8a, 0x31, 0x45, 0x30, 0x43,
	0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x3c, 0x4f, 0x43, 0x46, 0x20, 0x44, 0x65, 0x76, 0x69, 0x63,
	0x65, 0x20, 0x54, 0x45, 0x53, 0x54, 0x3a, 0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x28, 0x33, 0x66,
	0x65, 0x39, 0x38, 0x35, 0x61, 0x30, 0x2d, 0x64, 0x38, 0x38, 0x39, 0x2d, 0x34, 0x36, 0x38, 0x35,
	0x2d, 0x39, 0x30, 0x66, 0x34, 0x2d, 0x62, 0x36, 0x33, 0x37, 0x35, 0x34, 0x63, 0x31, 0x65, 0x66,
	0x34, 0x61, 0x29, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x0d, 0x4f, 0x43,
	0x46, 0x20, 0x48, 0x41, 0x20, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x31, 0x1c, 0x30, 0x1a, 0x06,
	0x03, 0x55, 0x04, 0x0a, 0x13, 0x13, 0x53, 0x61, 0x6d, 0x73, 0x75, 0x6e, 0x67, 0x20, 0x45, 0x6c,
	0x65, 0x63, 0x74, 0x72, 0x6f, 0x6e, 0x69, 0x63, 0x73, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55,
	0x04, 0x06, 0x13, 0x02, 0x4b, 0x52, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce,
	0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x20,
	0x04, 0x3a, 0xc1, 0x90, 0xc9, 0x3a, 0x28, 0x8c, 0xf8, 0xe9, 0xff, 0x78, 0xd8, 0x08, 0x41, 0x23,
	0x40, 0x37, 0x25, 0xd5, 0x43, 0xb7, 0x8e, 0xfc, 0x58, 0x49, 0x3f, 0x8b, 0x8b, 0xa0, 0xc7, 0xc8,
	0x77, 0x0d, 0x11, 0xe1, 0x1b, 0x9e, 0x2c, 0xae, 0x64, 0x91, 0x74, 0x66, 0xf9, 0x2f, 0x8d, 0xa1,
	0xb8, 0x33, 0x6a, 0x14, 0x21, 0x24, 0x30, 0x63, 0x3c, 0x2d, 0xed, 0xb0, 0x52, 0x35, 0x09, 0xa5,
	0xfe, 0xa3, 0x81, 0x8e, 0x30, 0x81, 0x8b, 0x30, 0x3c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05,
	0x07, 0x01, 0x01, 0x04, 0x30, 0x30, 0x2e, 0x30, 0x2c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05,
	0x07, 0x30, 0x01, 0x86, 0x20, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x6f, 0x63, 0x73, 0x70,
	0x2d, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x73, 0x61, 0x6d, 0x73, 0x75, 0x6e, 0x67, 0x69, 0x6f, 0x74,
	0x73, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04,
	0x04, 0x03, 0x02, 0x06, 0xc0, 0x30, 0x3b, 0x06, 0x03, 0x55, 0x1d, 0x1f, 0x04, 0x34, 0x30, 0x32,
	0x30, 0x30, 0xa0, 0x2e, 0xa0, 0x2c, 0x86, 0x2a, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x63,
	0x72, 0x6c, 0x2d, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x73, 0x61, 0x6d, 0x73, 0x75, 0x6e, 0x67, 0x69,
	0x6f, 0x74, 0x73, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x68, 0x61, 0x76, 0x31, 0x63, 0x61, 0x2e, 0x63,
	0x72, 0x6c, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x05, 0x20,
	0x03, 0x47, 0x20, 0x30, 0x44, 0x02, 0x20, 0x3c, 0xe2, 0x53, 0x1f, 0x62, 0xbe, 0x4c, 0xbb, 0x34,
	0x2c, 0xed, 0x78, 0x29, 0x2e, 0xd4, 0x7d, 0xba, 0x6e, 0x27, 0xec, 0xe4, 0x93, 0x5e, 0xfa, 0x63,
	0x99, 0x6f, 0x32, 0x82, 0xc7, 0x34, 0x9d, 0x02, 0x20, 0x0c, 0x4f, 0xab, 0x7b, 0x90, 0xf0, 0x56,
	0xa2, 0xd5, 0x71, 0xdc, 0xb1, 0x27, 0x2d, 0xc0, 0xaa, 0x60, 0x4e, 0xc9, 0xf4, 0xd9, 0x64, 0x0e,
	0x2e, 0x69, 0x09, 0xe9, 0x50, 0xcd, 0xde, 0xb1, 0x52
};

unsigned char factory_key_AES[] =
{
	0x3F, 0xB7, 0x23, 0x14, 0xED, 0xFF, 0x3D, 0xDD, 0x69, 0x65, 0xAB, 0xD2, 0x06, 0x6A, 0x29, 0x49,
	0x0E, 0x84, 0x0F, 0x53, 0xEF, 0xFC, 0x41, 0x2A, 0xAA, 0xB1, 0xDE, 0x1A, 0xA5, 0xA6, 0x39, 0x4B
};

static hal_data write_factory_key;
static hal_data write_factory_cert;

void sl_keymgr_test(void)
{
	_sl_init_keytest();

	ST_SET_PACK(sl_keymgr);

	//write_factory_key.data = EC_Private_Key;
	//write_factory_key.data_len = sizeof(EC_Private_Key);
	//write_factory_cert.data = HA_IOT_Device_Cert;
	//write_factory_cert.data_len = sizeof(HA_IOT_Device_Cert);
	//sedbg("\n\r Start write_factory\n");
	//for (int i = 0; i < RO_VALID_RANGE; ++i) {
	//	/* Write Cert */
	//	se_ameba_hal_write_factory_cert(i, &write_factory_cert);
	//}
	//for (int i = 0; i < 4; ++i) {
	//	/* Write Key */
	//	se_ameba_hal_write_factory_key(i, &write_factory_key);
	//}
	//write_factory_key.data = factory_key_AES;
	//write_factory_key.data_len = sizeof(factory_key_AES);
	//for (int i = 4; i < RO_VALID_RANGE; ++i) {
	//	/* Write Cert and Key */
	//	se_ameba_hal_write_factory_key(i, &write_factory_key);
	//}
	//sedbg("\n\r Done write_factory\n\n");


	ST_SET_SMOKE1(sl_keymgr, SL_TEST_KEY_TRIAL, SL_TEST_KEY_LIMIT_TIME, "Set symmetric key in RO area", set_sym_key_ro);
	ST_SET_SMOKE1(sl_keymgr, SL_TEST_KEY_TRIAL, SL_TEST_KEY_LIMIT_TIME, "Get symmetric key in RO area", get_sym_key_ro);
	ST_SET_SMOKE1(sl_keymgr, SL_TEST_KEY_TRIAL, SL_TEST_KEY_LIMIT_TIME, "Remove symmetric key in RO area", remove_sym_key_ro);
	ST_SET_SMOKE1(sl_keymgr, SL_TEST_KEY_TRIAL, SL_TEST_KEY_LIMIT_TIME, "Generate symmetric key in RO area", generate_sym_key_ro);

	ST_SET_SMOKE1(sl_keymgr, SL_TEST_KEY_TRIAL, SL_TEST_KEY_LIMIT_TIME, "Set public key in RO area", set_public_key_ro);
	ST_SET_SMOKE1(sl_keymgr, SL_TEST_KEY_TRIAL, SL_TEST_KEY_LIMIT_TIME, "Get public key in RO area", get_public_key_ro);
	ST_SET_SMOKE1(sl_keymgr, SL_TEST_KEY_TRIAL, SL_TEST_KEY_LIMIT_TIME, "Remove public key in RO area", remove_public_key_ro);
	ST_SET_SMOKE1(sl_keymgr, SL_TEST_KEY_TRIAL, SL_TEST_KEY_LIMIT_TIME, "Generate public key in RO area", generate_public_key_ro);

	ST_SET_SMOKE1(sl_keymgr, SL_TEST_KEY_TRIAL, SL_TEST_KEY_LIMIT_TIME, "Set private key in RO area", set_private_key_ro);
	ST_SET_SMOKE1(sl_keymgr, SL_TEST_KEY_TRIAL, SL_TEST_KEY_LIMIT_TIME, "Get private key in RO area", get_private_key_ro);
	ST_SET_SMOKE1(sl_keymgr, SL_TEST_KEY_TRIAL, SL_TEST_KEY_LIMIT_TIME, "Remove private key in RO area", remove_private_key_ro);
	ST_SET_SMOKE1(sl_keymgr, SL_TEST_KEY_TRIAL, SL_TEST_KEY_LIMIT_TIME, "Generate private key in RO area", generate_private_key_ro);

	ST_SET_SMOKE(sl_keymgr, SL_TEST_KEY_TRIAL, SL_TEST_KEY_LIMIT_TIME, "Set symmetric key in RW area", set_sym_key_rw);
	ST_SET_SMOKE(sl_keymgr, SL_TEST_KEY_TRIAL, SL_TEST_KEY_LIMIT_TIME, "Get symmetric key in RW area", get_sym_key_rw);
	ST_SET_SMOKE(sl_keymgr, SL_TEST_KEY_TRIAL, SL_TEST_KEY_LIMIT_TIME, "Remove symmetric key in RW area", remove_sym_key_rw);
	ST_SET_SMOKE(sl_keymgr, SL_TEST_KEY_TRIAL, SL_TEST_KEY_LIMIT_TIME, "Generate symmetric key in RW area", generate_sym_key_rw);

	ST_SET_SMOKE(sl_keymgr, SL_TEST_KEY_TRIAL, SL_TEST_KEY_LIMIT_TIME, "Set public key in RW area", set_public_key_rw);
	ST_SET_SMOKE(sl_keymgr, SL_TEST_KEY_TRIAL, SL_TEST_KEY_LIMIT_TIME, "Get public key in RW area", get_public_key_rw);
	ST_SET_SMOKE(sl_keymgr, SL_TEST_KEY_TRIAL, SL_TEST_KEY_LIMIT_TIME, "Remove public key in RW area", remove_public_key_rw);
	ST_SET_SMOKE(sl_keymgr, SL_TEST_KEY_TRIAL, SL_TEST_KEY_LIMIT_TIME, "Generate public key in RW area", generate_public_key_rw);

	ST_SET_SMOKE(sl_keymgr, SL_TEST_KEY_TRIAL, SL_TEST_KEY_LIMIT_TIME, "Set private key in RW area", set_private_key_rw);
	ST_SET_SMOKE(sl_keymgr, SL_TEST_KEY_TRIAL, SL_TEST_KEY_LIMIT_TIME, "Get private key in RW area", get_private_key_rw);
	ST_SET_SMOKE(sl_keymgr, SL_TEST_KEY_TRIAL, SL_TEST_KEY_LIMIT_TIME, "Remove private key in RW area", remove_private_key_rw);

	ST_RUN_TEST(sl_keymgr);
	ST_RESULT_TEST(sl_keymgr);

	_sl_deinit_keytest();
}

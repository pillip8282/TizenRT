#include <tinyara/config.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <dirent.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <wifi_manager/wifi_manager.h>
#ifdef CONFIG_WIFI_PROFILE_SECURESTORAGE
#include <mbedtls/see_api.h>
#endif
#include "wifi_common.h"
#include "wifi_profile.h"

//#define WIFI_PROFILE_USE_ETC
#define WIFI_PROFILE_PATH "/mnt/"
#define WIFI_PROFILE_FILENAME "wifi.conf"

#define DELIMITER "\t"
#define DELI_LEN 1

#ifdef CONFIG_WIFI_PROFILE_SECURESTORAGE
#define WIFI_PROFILE_SS_INDEX 1
#endif

#define ENCODE_STRING(buf, size, data, pos)					\
	do {													\
		snprintf(buf + pos, size, "%s" DELIMITER, data);	\
		pos += (strlen(data) + DELI_LEN);					\
	} while (0)

#define ENCODE_INTEGER(buf, size, data, pos)				\
	do {													\
		char conv[12];										\
		snprintf(buf + pos, size, "%d" DELIMITER, data);	\
		sprintf(conv, "%d", data);							\
		pos += (strlen(conv) + DELI_LEN);					\
	} while (0)

#define DECODE_STRING(buf, data, pos)				\
	do {											\
		sscanf(buf + pos, "%s", data);				\
		pos += ((int)(strlen(data)) + DELI_LEN);	\
	} while (0)

#define DECODE_INTEGER(buf, data, pos)			\
	do {										\
		char conv[12];							\
		int tmp;								\
		sscanf(buf + pos, "%d", &tmp);			\
		sprintf(conv, "%d", tmp);				\
		data = tmp;								\
		pos += (strlen(conv) + DELI_LEN);		\
	} while (0)

/*
 * Internal Functions
 */

int _wifi_profile_serialize(char *buf, uint32_t buf_size, wifi_manager_ap_config_s *config)
{
	memset(buf, 0, buf_size);
	int pos = 0;
	ENCODE_STRING(buf, buf_size, config->ssid, pos);
	ENCODE_INTEGER(buf, buf_size, config->ssid_length, pos);
	int auth_type = (int)config->ap_auth_type;
	ENCODE_INTEGER(buf, buf_size, auth_type, pos);

	if (config->ap_auth_type == WIFI_MANAGER_AUTH_OPEN) {
		return strlen(buf) + 1;
	}

	ENCODE_STRING(buf, buf_size, config->passphrase, pos);
	ENCODE_INTEGER(buf, buf_size, config->passphrase_length, pos);

	int crypto_type = (int)config->ap_crypto_type;
	ENCODE_INTEGER(buf, buf_size, crypto_type, pos);

	return strlen(buf) + 1;
}

void _wifi_profile_deserialize(wifi_manager_ap_config_s *config, char *buf)
{
	int pos = 0;
	DECODE_STRING(buf, config->ssid, pos);
	DECODE_INTEGER(buf, config->ssid_length, pos);
	int auth_type = 0;
	DECODE_INTEGER(buf, auth_type, pos);
	config->ap_auth_type = (wifi_manager_ap_auth_type_e)auth_type;
	if (config->ap_auth_type == WIFI_MANAGER_AUTH_OPEN) {
		return;
	}
	DECODE_STRING(buf, config->passphrase, pos);
	DECODE_INTEGER(buf, config->passphrase_length, pos);
	int crypto_type = 0;
	DECODE_INTEGER(buf, crypto_type, pos);
	config->ap_crypto_type = (wifi_manager_ap_crypto_type_e)crypto_type;
}

#ifdef CONFIG_WIFI_PROFILE_SECURESTORAGE
int _wifi_profile_store_file(char *buf, unsigned int buf_size)
{
#ifdef WIFI_PROFILE_USE_ETC
	// Temporary code. /etc should be created as default
	DIR *dir = opendir(WIFI_PROFILE_PATH);
	if (!dir) {
		printf("error reason (%d)\n", errno);
		if (errno == ENOENT || errno == ENOTDIR) {
			// create file
			ret = mkdir(WIFI_PROFILE_PATH, 0777);
			if (ret < 0) {
				return WIFI_UTILS_FILE_ERROR;
			}
		} else {
			return WIFI_UTILS_FILE_ERROR;
		}
	}
#endif
	FILE *fp = fopen(WIFI_PROFILE_PATH WIFI_PROFILE_FILENAME, "w+");
	if (!fp) {
		printf("file open error(%d)\n", errno);
		return -1;
	}

	int ret = fwrite(buf, 1, buf_size, fp);
	if (ret < 0) {
		printf("file write error(%d)\n", errno);
		fclose(fp);
		return -1;
	}
	fclose(fp);
	return 0;
}


int _wifi_profile_read_file(char *buf, unsigned int buf_size)
{
	FILE *fp = fopen(WIFI_PROFILE_PATH WIFI_PROFILE_FILENAME, "r");
	if (!fp) {
		printf("file open error(%d)\n", errno);
		return -1;
	}

	int ret = fread(buf, 1, buf_size, fp);
	if (ret < 0) {
		printf("fread fail\n");
		fclose(fp);
		return -1;
	}
	fclose(fp);
	return 0;
}
#endif

/*
 * Public Functions
 */

wifi_utils_result_e wifi_profile_write(wifi_manager_ap_config_s *config)
{
	char buf[256];
	int ret = 0, len = 0;
	len = _wifi_profile_serialize(buf, 256, config);
	if (len < 0) {
		return WIFI_UTILS_FAIL;
	}
	printf("store data to file: buffer len(%d)\n", len);
#ifdef CONFIG_WIFI_PROFILE_SECURESTORAGE
	ret = see_write_secure_storage((unsigned char *)buf, (unsigned int)len, WIFI_PROFILE_SS_INDEX);
	if (ret != SEE_OK) {
		printf("Write SS fail(%d)\n", ret);
		return WIFI_UTILS_FILE_ERROR;
	}
#else
	ret = _wifi_profile_store_file(buf, len);
	if (ret < 0) {
		return WIFI_UTILS_FILE_ERROR;
	}
#endif

	return WIFI_UTILS_SUCCESS;
}


wifi_utils_result_e wifi_profile_read(wifi_manager_ap_config_s *config)
{
	char buf[256] = {0,};
	int ret = -1;
#ifdef CONFIG_WIFI_PROFILE_SECURESTORAGE
	unsigned int readlen = 256;
	ret = see_read_secure_storage((unsigned char *)buf, &readlen, WIFI_PROFILE_SS_INDEX);
	if (ret != SEE_OK) {
		return WIFI_UTILS_FILE_ERROR;
	}
#else
	ret = _wifi_profile_read_file(buf, 256);
	if (ret < 0) {
		return WIFI_UTILS_FILE_ERROR;
	}
#endif

	_wifi_profile_deserialize(config, buf);

	return WIFI_UTILS_SUCCESS;
}

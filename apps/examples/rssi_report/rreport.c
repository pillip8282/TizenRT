/****************************************************************************
 *
 * Copyright 2016 Samsung Electronics All Rights Reserved.
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

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <tinyara/config.h>
#include <stdint.h>
#include <wifi_manager/wifi_manager.h>
#include <curl/curl.h>
#include <json/cJSON.h>

/****************************************************************************
 * Private Data
 ****************************************************************************/


/****************************************************************************
* Public Data
****************************************************************************/
#define USAGE \
	"rreport url"

static char *g_url = NULL;

//#define MYURL "http://127.0.0.1:5000/handle_post"
#define ERR										\
	do {										\
		printf("%s%d\n", __FILE__,  __LINE__);	\
		return -1;								\
	} while (0)

/*
 * External Function
 */
extern int sync_time(void);

/*
 * Private Function
 */
static int rr_http_post(char *str)
{
	char agent[1024] = { 0, };
	struct curl_slist *headers = NULL;
	curl_global_init(CURL_GLOBAL_ALL);

	CURL* ctx = curl_easy_init();
	if (!ctx) {
		ERR;
		return -1;
	}

	printf("url: %s\n", g_url);

	CURLcode ret = curl_easy_setopt(ctx, CURLOPT_URL, g_url);
	if (ret != CURLE_OK) {
		ERR;
		return -1;
	}

	snprintf(agent, sizeof agent, "libcurl/%s",
			 curl_version_info(CURLVERSION_NOW)->version);
	agent[sizeof agent - 1] = 0;
	curl_easy_setopt(ctx, CURLOPT_USERAGENT, agent);

	headers = curl_slist_append(headers, "Expect:");
	headers = curl_slist_append(headers, "Content-Type: application/json");
	curl_easy_setopt(ctx, CURLOPT_HTTPHEADER, headers);

	curl_easy_setopt(ctx, CURLOPT_POSTFIELDS, str);
	curl_easy_setopt(ctx, CURLOPT_POSTFIELDSIZE, -1L);

	ret = curl_easy_perform(ctx);
	if (ret != CURLE_OK) {
		ERR;
		printf("error(%d)\n", ret);
		goto cleanup;
	} else {
		printf("success\n");
	}

    /*  get response  */
	long statLong = 0;
	if (CURLE_OK == curl_easy_getinfo(ctx,CURLINFO_HTTP_CODE, &statLong)) {
		printf("Response code %ld\n", statLong);
	}
	if (CURLE_OK == curl_easy_getinfo(ctx, CURLINFO_CONTENT_TYPE, &statLong)) {
		printf("content type code %ld\n", statLong);
	}

cleanup:
	curl_slist_free_all(headers);
	curl_easy_cleanup(ctx);

	return 0;
}

int send_rssi(void)
{
	int value[] = {-78, -23, -35, -45, -6};


	cJSON *rssi = cJSON_CreateObject();
	if (!rssi) {
		ERR;
		return -1;
	}
	char cur_time[64];

	if (rr_get_time(cur_time, 64) < 0) {
		ERR;
		return -1;
	}
	printf("cur time %s\n", cur_time);

	cJSON *time = cJSON_CreateString(cur_time);
	if (!time) {
		ERR;
		return -1;
	}

	cJSON_AddItemToObject(rssi, "time", time);

	cJSON *period = cJSON_CreateString("500");
	if (!time) {
		ERR;
		return -1;
	}

	cJSON_AddItemToObject(rssi, "period", period);

	cJSON *item = cJSON_CreateIntArray(value, 5);
	if (!item) {
		ERR; return -1;
	}
	//printf("size %d\n", cJSON_GetArraySize(item));

	cJSON_AddItemToObject(rssi, "rssi", item);

	char *string = cJSON_PrintUnformatted(rssi);
	printf("Result:\n%s\n", string);

	cJSON_Delete(rssi);

	rr_http_post(string);

	return 0;
}


#ifdef CONFIG_BUILD_KERNEL
int main(int argc, FAR char *argv[])
#else
int rreport_main(int argc, char *argv[])
#endif
{
	if (argc < 2) {
		printf("invalid argument\n");
		return -1;
	}

	g_url = argv[1];
	printf("hello rssi report\n");

	sync_time();

	for (int i = 0; i < 10; ++i) {
		send_rssi();
		usleep(500000);
	}

	return 0;
}

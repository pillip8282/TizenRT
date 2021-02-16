/****************************************************************************
 *
 * Copyright 2021 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License\n");
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

#ifndef _WIFI_TEST_UTILS_H__
#define _WIFI_TEST_UTILS_H__
#define WO_ERROR(res) printf("[WO][ERR] code(%d) (%d): %s\t%s:%d\n",	\
							 res, errno, __FUNCTION__, __FILE__, __LINE__)

#if 0
#define WO_TEST_SIGNAL(conn, queue)										\
	do {																\
		printf("[WO] T%d send signal\t %s:%s:%d\n", getpid(), __FUNCTION__, __FILE__, __LINE__); \
		int ssres = pthread_mutex_lock(&queue->lock);					\
		if (ssres != 0) {												\
			printf("[WO] pthread lock fail %s:%d\n", __FILE__, __LINE__); \
		}																\
		ssres = wo_add_queue(conn, queue);								\
		if (ssres != 0) {												\
			assert(0);													\
		}																\
		ssres = pthread_cond_signal(&queue->signal);					\
		if (ssres != 0) {												\
			printf("[WO] pthread signal fail %s:%d\n", __FILE__, __LINE__); \
		}																\
		ssres = pthread_mutex_unlock(&queue->lock);						\
		if (ssres != 0) {												\
			printf("[WO] pthread unlock fail %s:%d\n", __FILE__, __LINE__); \
		}																\
	} while (0)

#define WO_TEST_WAIT(conn, queue)										\
	do {																\
		printf("[WO] T%d wait signal\t %s:%s:%d\n", getpid(), __FUNCTION__, __FILE__, __LINE__); \
		sem_wait(&queue->signal);										\
		int swres = wo_dequeue(&conn, queue);							\
		if (swres != 0) {												\
			assert(0);													\
		}																\
	} while (0)
#endif


struct wo_queue {
	pthread_mutex_t lock;
	pthread_cond_t  signal;
	//sem_t lock;
	//sem_t signal;
	int queue[10];
	int front;
	int rear;
};

int wo_add_queue(int conn, struct wo_queue *queue);
int wo_dequeue(int *conn, struct wo_queue *queue);
struct wo_queue *wo_create_queue(void);
void wo_destroy_queue(struct wo_queue *queue);

void WO_TEST_SIGNAL(int conn, struct wo_queue *queue);
void WO_TEST_WAIT(int *conn, struct wo_queue *queue);

#endif // #define _WIFI_TEST_UTILS_H__

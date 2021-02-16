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
#include <tinyara/config.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <semaphore.h>
#include <errno.h>
#include <wifi_manager/wifi_manager.h>
#include "wm_test_utils.h"
/*
 * queue
 */
#define WO_QUEUE_SIZE 10

int wo_is_empty(struct wo_queue *queue)
{
	if (queue->rear == queue->front) {
		return 1;
	}
	return 0;
}

int wo_is_full(struct wo_queue *queue)
{
	int tmp = (queue->front + 1) % WO_QUEUE_SIZE;
	if (tmp == queue->rear) {
		return 1;
	}
	return 0;
}

int wo_add_queue(int conn, struct wo_queue *queue)
{
	if (wo_is_full(queue)) {
		/*  if queue is full then main task which read event are not working
		 so reboot it*/
		assert(0);
	}
	queue->front = (queue->front + 1) % WO_QUEUE_SIZE;
	queue->queue[queue->front] = conn;

	return 0;
}

int wo_dequeue(int *conn, struct wo_queue *queue)
{
	if (wo_is_empty(queue)) {
		return -1;
	}
	queue->rear = (queue->rear + 1) % WO_QUEUE_SIZE;
	*conn = queue->queue[queue->rear];

	return 0;
}

struct wo_queue *wo_create_queue(void)
{
	struct wo_queue *queue = (struct wo_queue *)malloc(sizeof(struct wo_queue));
	if (!queue) {
		return NULL;
	}
#if 0
	int res = sem_init(&queue->lock, 0, 1);
	if (res < 0) {
		printf("[WO] fail to initialize lock %d\n", errno);
		free(queue);
		return NULL;
	}
	res = sem_init(&queue->signal, 0, 0);
	if (res < 0) {
		printf("[WO] fail to intiailize signal\n", errno);
		sem_destroy(&queue->lock);
		free(queue);
	}
#endif

	int res = pthread_mutex_init(&queue->lock, NULL);
	if (res < 0) {
		printf("[WO] fail to initialize lock %d\n", errno);
		free(queue);
		return NULL;
	}
	res = pthread_cond_init(&queue->signal, NULL);
	if (res < 0) {
		printf("[WO] fail to intiailize signal\n", errno);
		pthread_mutex_destroy(&queue->lock);
		free(queue);
	}

	queue->front = -1;
	queue->rear = -1;

	return queue;
}

void wo_destroy_queue(struct wo_queue *queue)
{
	if (!queue) {
		return;
	}
#if 0
	sem_destroy(&queue->lock);
	sem_destroy(&queue->signal);
#endif
	pthread_mutex_destroy(&queue->lock);
	pthread_cond_destroy(&queue->signal);
	free(queue);
}

void WO_TEST_SIGNAL(int conn, struct wo_queue *queue)
{
	printf("[WO] T%d send signal\t %s:%s:%d\n", getpid(), __FUNCTION__, __FILE__, __LINE__);
	int ssres = pthread_mutex_lock(&queue->lock);
	if (ssres != 0) {
		printf("[WO] pthread lock fail %s:%d\n", __FILE__, __LINE__);
	}
	ssres = wo_add_queue(conn, queue);
	if (ssres != 0) {
		assert(0);
	}
	ssres = pthread_cond_signal(&queue->signal);
	if (ssres != 0) {
		printf("[WO] pthread signal fail %s:%d\n", __FILE__, __LINE__);
	}
	ssres = pthread_mutex_unlock(&queue->lock);
	if (ssres != 0) {
		printf("[WO] pthread unlock fail %s:%d\n", __FILE__, __LINE__);
	}
}

void WO_TEST_WAIT(int *conn, struct wo_queue *queue)
{
	printf("[WO] T%d wait signal\t %s:%s:%d\n", getpid(), __FUNCTION__, __FILE__, __LINE__);
	int ssres = pthread_mutex_lock(&queue->lock);
	if (ssres != 0) {
		printf("[WO] pthread lock fail %s:%d\n", __FILE__, __LINE__);
	}
	ssres = wo_dequeue(conn, queue);
	if (ssres == 0) {
		ssres = pthread_mutex_unlock(&queue->lock);
		if (ssres != 0) {
			printf("[WO] pthread unlock fail %s:%d\n", __FILE__, __LINE__);
		}
		return;
	}

	ssres = pthread_cond_wait(&queue->signal, &queue->lock);
	if (ssres != 0) {
		printf("[WO] pthread signal fail %s:%d\n", __FILE__, __LINE__);
	}

	ssres = wo_dequeue(conn, queue);
	if (ssres != 0) {
		assert(0);
	}

	ssres = pthread_mutex_unlock(&queue->lock);
	if (ssres != 0) {
		printf("[WO] pthread unlock fail %s:%d\n", __FILE__, __LINE__);
	}
}


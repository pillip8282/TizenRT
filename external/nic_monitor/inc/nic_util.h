/****************************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
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

#ifndef _NIC_UTILS_H__
#define _NIC_UTILS_H__

#ifdef LINUX
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#endif

#define NIC_LOG printf

#ifdef LINUX
#define NIC_ENTRY printf("%lx\t--> %s(%s:%d)\n", pthread_self(), __FUNCTION__, __FILE__, __LINE__)
#define NIC_OUT	printf("%lx\t<-- %s(%s:%d)\n", pthread_self(), __FUNCTION__, __FILE__, __LINE__)
#define NIC_ERR	printf("%lx\tFAIL %s(%s:%d)\n", pthread_self(), __FUNCTION__, __FILE__, __LINE__)
#define NIC_PASS printf("%lx\tPASS %s(%s:%d)\n", pthread_self(), __FUNCTION__, __FILE__, __LINE__)
#else
#define NIC_ENTRY printf("%lx\t--> %s(%s:%d)\n", getpid(), __FUNCTION__, __FILE__, __LINE__)
#define NIC_OUT printf("%lx\t<-- %s(%s:%d)\n", getpid(), __FUNCTION__, __FILE__, __LINE__)
#define NIC_ERR printf("%lx\tFAIL %s(%s:%d)\n", getpid(), __FUNCTION__, __FILE__, __LINE__)
#define NIC_PASS printf("%lx\tPASS %s(%s:%d)\n", getpid(), __FUNCTION__, __FILE__, __LINE__)
#endif

#endif // _NIC_UTILS_H__

#ifndef _NIC_UTILS_H__
#define _NIC_UTILS_H__

#ifdef LINUX
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

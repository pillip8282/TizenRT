#ifndef _SECLINK_DRIVER_UTILS_H__
#define _SECLINK_DRIVER_UTILS_H__
#ifndef LINUX
#include <debug.h>
#endif
#include <time.h>
#include <tinyara/timer.h>

#ifndef LINUX
#define SLDRV_LOG sevdbg
#else
#define SLDRV_LOG printf
#endif

#define SLDRV_TAG "[SECLINK_DRV]"

#define SLDRV_ERR(fd)										\
	do {													\
		SLDRV_LOG(SL_TAG"%s:%d ret(%d) code(%s))\n",		\
				  __FILE__, __LINE__, fd, strerror(errno));	\
	} while (0)

#define SLDRV_ENTER											\
	do {													\
		SLDRV_LOG(SLDRV_TAG"%s:%d\n", __FILE__, __LINE__);	\
	} while (0)

/* #define SLDRV_CALL(ret, res, method, param)								\ */
/* 	do {																\ */
/* 		struct timespec tstart, tend;									\ */
/* 		uint32_t telapsed;												\ */
/* 		if (se->ops->method) {											\ */
/* 			clock_gettime(CLOCK_REALTIME, &tstart);						\ */
/* 			res = (se->ops->method)param;								\ */
/* 			clock_gettime(CLOCK_REALTIME, &tend);						\ */
/* 			telapsed = sdrv_calc_elasped(&tstart, &tend);					\ */
/* 			printf("[pdrv] "#method " res %d elapsed %u %u ms\n", res, telapsed, telapsed/1000000); \ */
/* 		} else {														\ */
/* 			ret = -ENOSYS;												\ */
/* 		}																\ */
/* 	} while (0) */

#define SLDRV_CALL(ret, res, method, param)		\
	do {										\
		if (se->ops->method) {					\
			lldbg("[pdrv]-->"#method"\n");		\
			res = (se->ops->method)param;		\
			lldbg("[pdrv]<--"#method"\n");		\
		} else {								\
			ret = -ENOSYS;						\
		}										\
	} while (0)

#if 0
void get_frt_time(struct timer_status_s *ts);
uint32_t sdrv_calc_elapsed2(struct timer_status_s *start, struct timer_status_s *end);
#endif
uint32_t sdrv_calc_elasped(struct timespec *start, struct timespec *end);

#endif // _SECLINK_DRIVER_UTILS_H__

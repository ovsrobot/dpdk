/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ramaxel Memory Technology, Ltd
 */

#ifndef _SPNIC_COMPAT_H_
#define _SPNIC_COMPAT_H_

#include <stdint.h>
#include <stdbool.h>
#include <sys/time.h>
#include <unistd.h>
#include <pthread.h>
#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_memzone.h>
#include <rte_memcpy.h>
#include <rte_malloc.h>
#include <rte_atomic.h>
#include <rte_spinlock.h>
#include <rte_cycles.h>
#include <rte_log.h>
#include <rte_config.h>
#include <rte_io.h>

typedef uint8_t   u8;
typedef int8_t    s8;
typedef uint16_t  u16;
typedef uint32_t  u32;
typedef int32_t   s32;
typedef uint64_t  u64;

#ifndef BIT
#define BIT(n) (1 << (n))
#endif

#define upper_32_bits(n) ((u32)(((n) >> 16) >> 16))
#define lower_32_bits(n) ((u32)(n))

#define SPNIC_MEM_ALLOC_ALIGN_MIN	1

#define SPNIC_DRIVER_NAME "spnic"

extern int spnic_logtype;

#define PMD_DRV_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, spnic_logtype, \
		SPNIC_DRIVER_NAME ": " fmt "\n", ##args)

/* Bit order interface */
#define cpu_to_be16(o) rte_cpu_to_be_16(o)
#define cpu_to_be32(o) rte_cpu_to_be_32(o)
#define cpu_to_be64(o) rte_cpu_to_be_64(o)
#define cpu_to_le32(o) rte_cpu_to_le_32(o)
#define be16_to_cpu(o) rte_be_to_cpu_16(o)
#define be32_to_cpu(o) rte_be_to_cpu_32(o)
#define be64_to_cpu(o) rte_be_to_cpu_64(o)
#define le32_to_cpu(o) rte_le_to_cpu_32(o)

#define ARRAY_LEN(arr) ((sizeof(arr) / sizeof((arr)[0])))

#define SPNIC_MUTEX_TIMEOUT	10
#define SPNIC_S_TO_MS_UNIT	1000
#define SPNIC_S_TO_NS_UNIT	1000000

static inline unsigned long clock_gettime_ms(void)
{
	struct timespec tv;

	(void)clock_gettime(CLOCK_MONOTONIC_COARSE, &tv);

	return (unsigned long)tv.tv_sec * SPNIC_S_TO_MS_UNIT +
	       (unsigned long)tv.tv_nsec / SPNIC_S_TO_NS_UNIT;
}

#define jiffies	clock_gettime_ms()
#define msecs_to_jiffies(ms)	(ms)

#define time_after(a, b)	((long)((b) - (a)) < 0)
#define time_before(a, b)	time_after(b, a)

/**
 * Convert data to big endian 32 bit format
 *
 * @param data
 *   The data to convert
 * @param len
 *   Length of data to convert, must be Multiple of 4B
 */
static inline void spnic_cpu_to_be32(void *data, int len)
{
	int i, chunk_sz = sizeof(u32);
	u32 *mem = data;

	if (!data)
		return;

	len = len / chunk_sz;

	for (i = 0; i < len; i++) {
		*mem = cpu_to_be32(*mem);
		mem++;
	}
}

/**
 * Convert data from big endian 32 bit format
 *
 * @param data
 *   The data to convert
 * @param len
 *   Length of data to convert, must be Multiple of 4B
 */
static inline void spnic_be32_to_cpu(void *data, int len)
{
	int i, chunk_sz = sizeof(u32);
	u32 *mem = data;

	if (!data)
		return;

	len = len / chunk_sz;

	for (i = 0; i < len; i++) {
		*mem = be32_to_cpu(*mem);
		mem++;
	}
}

static inline u16 ilog2(u32 n)
{
	u16 res = 0;

	while (n > 1) {
		n >>= 1;
		res++;
	}

	return res;
}

static inline int spnic_mutex_init(pthread_mutex_t *pthreadmutex,
				   const pthread_mutexattr_t *mattr)
{
	int err;

	err = pthread_mutex_init(pthreadmutex, mattr);
	if (unlikely(err))
		PMD_DRV_LOG(ERR, "Initialize mutex failed, error: %d", err);

	return err;
}

static inline int spnic_mutex_destroy(pthread_mutex_t *pthreadmutex)
{
	int err;

	err = pthread_mutex_destroy(pthreadmutex);
	if (unlikely(err))
		PMD_DRV_LOG(ERR, "Destroy mutex failed, error: %d", err);

	return err;
}

static inline int spnic_mutex_lock(pthread_mutex_t *pthreadmutex)
{
	struct timespec tout;
	int err;

	(void)clock_gettime(CLOCK_MONOTONIC_COARSE, &tout);

	tout.tv_sec += SPNIC_MUTEX_TIMEOUT;
	err = pthread_mutex_timedlock(pthreadmutex, &tout);
	if (err)
		PMD_DRV_LOG(ERR, "Mutex lock failed, err: %d", err);

	return err;
}

static inline int spnic_mutex_unlock(pthread_mutex_t *pthreadmutex)
{
	return pthread_mutex_unlock(pthreadmutex);
}

#endif /* _SPNIC_COMPAT_H_ */

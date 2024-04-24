/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Arm Limited
 */

#include <stdalign.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/queue.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_memzone.h>
#include <rte_malloc.h>
#include <rte_eal_memconfig.h>
#include <rte_errno.h>
#include <rte_string_fns.h>

#include "rte_deque.h"

/* mask of all valid flag values to deque_create() */
#define __RTE_DEQUE_F_MASK (RTE_DEQUE_F_EXACT_SZ)
ssize_t
rte_deque_get_memsize_elem(unsigned int esize, unsigned int count)
{
	ssize_t sz;

	/* Check if element size is a multiple of 4B */
	if (esize % 4 != 0) {
		rte_log(RTE_LOG_ERR, rte_deque_log_type,
			"%s(): element size is not a multiple of 4\n",
			__func__);

		return -EINVAL;
	}

	/* count must be a power of 2 */
	if ((!RTE_IS_POWER_OF_2(count)) || (count > RTE_DEQUE_SZ_MASK)) {
		rte_log(RTE_LOG_ERR, rte_deque_log_type,
			"%s(): Requested number of elements is invalid,"
			"must be power of 2, and not exceed %u\n",
			__func__, RTE_DEQUE_SZ_MASK);

		return -EINVAL;
	}

	sz = sizeof(struct rte_deque) + (ssize_t)count * esize;
	sz = RTE_ALIGN(sz, RTE_CACHE_LINE_SIZE);
	return sz;
}

void
rte_deque_reset(struct rte_deque *d)
{
	d->head = 0;
	d->tail = 0;
}

int
rte_deque_init(struct rte_deque *d, const char *name, unsigned int count,
	unsigned int flags)
{
	int ret;

	/* compilation-time checks */
	RTE_BUILD_BUG_ON((sizeof(struct rte_deque) &
			  RTE_CACHE_LINE_MASK) != 0);

	/* future proof flags, only allow supported values */
	if (flags & ~__RTE_DEQUE_F_MASK) {
		rte_log(RTE_LOG_ERR, rte_deque_log_type,
			"%s(): Unsupported flags requested %#x\n",
			__func__, flags);
		return -EINVAL;
	}

	/* init the deque structure */
	memset(d, 0, sizeof(*d));
	ret = strlcpy(d->name, name, sizeof(d->name));
	if (ret < 0 || ret >= (int)sizeof(d->name))
		return -ENAMETOOLONG;
	d->flags = flags;

	if (flags & RTE_DEQUE_F_EXACT_SZ) {
		d->size = rte_align32pow2(count + 1);
		d->mask = d->size - 1;
		d->capacity = count;
	} else {
		if ((!RTE_IS_POWER_OF_2(count)) || (count > RTE_DEQUE_SZ_MASK)) {
			rte_log(RTE_LOG_ERR, rte_deque_log_type,
				"%s(): Requested size is invalid, must be power"
				" of 2, and not exceed the size limit %u\n",
				__func__, RTE_DEQUE_SZ_MASK);
			return -EINVAL;
		}
		d->size = count;
		d->mask = count - 1;
		d->capacity = d->mask;
	}

	return 0;
}

/* create the deque for a given element size */
struct rte_deque *
rte_deque_create(const char *name, unsigned int esize, unsigned int count,
		int socket_id, unsigned int flags)
{
	char mz_name[RTE_MEMZONE_NAMESIZE];
	struct rte_deque *d;
	const struct rte_memzone *mz;
	ssize_t deque_size;
	int mz_flags = 0;
	const unsigned int requested_count = count;
	int ret;

	/* for an exact size deque, round up from count to a power of two */
	if (flags & RTE_DEQUE_F_EXACT_SZ)
		count = rte_align32pow2(count + 1);

	deque_size = rte_deque_get_memsize_elem(esize, count);
	if (deque_size < 0) {
		rte_errno = -deque_size;
		return NULL;
	}

	ret = snprintf(mz_name, sizeof(mz_name), "%s%s",
		RTE_DEQUE_MZ_PREFIX, name);
	if (ret < 0 || ret >= (int)sizeof(mz_name)) {
		rte_errno = ENAMETOOLONG;
		return NULL;
	}

	/* reserve a memory zone for this deque. If we can't get rte_config or
	 * we are secondary process, the memzone_reserve function will set
	 * rte_errno for us appropriately - hence no check in this function
	 */
	mz = rte_memzone_reserve_aligned(mz_name, deque_size, socket_id,
					 mz_flags, alignof(struct rte_deque));
	if (mz != NULL) {
		d = mz->addr;
		/* no need to check return value here, we already checked the
		 * arguments above
		 */
		rte_deque_init(d, name, requested_count, flags);
		d->memzone = mz;
	} else {
		d = NULL;
		rte_log(RTE_LOG_ERR, rte_deque_log_type,
			"%s(): Cannot reserve memory\n", __func__);
	}
	return d;
}

/* free the deque */
void
rte_deque_free(struct rte_deque *d)
{
	if (d == NULL)
		return;

	/*
	 * Deque was not created with rte_deque_create,
	 * therefore, there is no memzone to free.
	 */
	if (d->memzone == NULL) {
		rte_log(RTE_LOG_ERR, rte_deque_log_type,
			"%s(): Cannot free deque, not created "
			"with rte_deque_create()\n", __func__);
		return;
	}

	if (rte_memzone_free(d->memzone) != 0)
		rte_log(RTE_LOG_ERR, rte_deque_log_type,
			"%s(): Cannot free memory\n", __func__);
}

/* dump the status of the deque on the console */
void
rte_deque_dump(FILE *f, const struct rte_deque *d)
{
	fprintf(f, "deque <%s>@%p\n", d->name, d);
	fprintf(f, "  flags=%x\n", d->flags);
	fprintf(f, "  size=%"PRIu32"\n", d->size);
	fprintf(f, "  capacity=%"PRIu32"\n", d->capacity);
	fprintf(f, "  head=%"PRIu32"\n", d->head);
	fprintf(f, "  tail=%"PRIu32"\n", d->tail);
	fprintf(f, "  used=%u\n", rte_deque_count(d));
	fprintf(f, "  avail=%u\n", rte_deque_free_count(d));
}

RTE_LOG_REGISTER_DEFAULT(rte_deque_log_type, ERR);

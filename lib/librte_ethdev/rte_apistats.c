/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 NTT TechnoCross Corporation
 */


#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <rte_log.h>
#include <rte_memzone.h>
#include <rte_lcore.h>

#include "rte_apistats.h"

/* Macros for printing using RTE_LOG */
#define RTE_LOGTYPE_APISTATS RTE_LOGTYPE_USER1

#define MZ_APISTATS "rte_apistats"

struct rte_apistats *rte_apicounts;

int rte_apistats_init(void)
{
	int i;
	const struct rte_memzone *mz = NULL;
	const unsigned int flags = 0;

	/** Allocate stats in shared memory fo multi process support */
	if (rte_eal_process_type() == RTE_PROC_SECONDARY) {
		mz = rte_memzone_lookup(MZ_APISTATS);
		if (mz == NULL) {
			RTE_LOG(ERR, APISTATS, "Cannot get info structure\n");
			return -1;
		}
		rte_apicounts = mz->addr;
	} else {
		/* RTE_PROC_PRIMARY */
		mz = rte_memzone_reserve(MZ_APISTATS, sizeof(*rte_apicounts),
			rte_socket_id(), flags);
		if (mz == NULL) {
			RTE_LOG(ERR, APISTATS, "Cannot reserve memory zone\n");
			return -ENOMEM;
		}
		rte_apicounts = mz->addr;
		memset(rte_apicounts, 0, sizeof(*rte_apicounts));
	}

	/* set up array for data */
	RTE_LCORE_FOREACH(i) {
		rte_apicounts->lcoreid_list[i] = 1;
		RTE_LOG(INFO, APISTATS, "Enable core usage for lcore %u\n", i);
	}
	return 0;
}

int rte_apistats_uninit(void)
{
	const struct rte_memzone *mz = NULL;
	/* free up the memzone */
	mz = rte_memzone_lookup(MZ_APISTATS);
	if (mz)
		rte_memzone_free(mz);
	return 0;
}

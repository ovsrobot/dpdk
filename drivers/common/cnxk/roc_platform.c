/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2019 Marvell International Ltd.
 */

#include <rte_log.h>

#include "roc_api.h"

int
plt_init(void)
{
	const struct rte_memzone *mz;

	mz = rte_memzone_lookup(PLT_MODEL_MZ_NAME);
	if (mz == NULL)
		mz = rte_memzone_reserve(PLT_MODEL_MZ_NAME,
					 sizeof(struct roc_model),
					 SOCKET_ID_ANY, 0);
	else
		return 0;

	if (mz == NULL) {
		plt_err("Failed to allocate memory for roc_model");
		return -ENOMEM;
	}
	roc_model_init(mz->addr);
	return 0;
}

RTE_LOG_REGISTER(cnxk_logtype_base, pmd.cnxk.base, NOTICE);

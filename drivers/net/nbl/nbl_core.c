/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 Nebulamatrix Technology Co., Ltd.
 */

#include "nbl_core.h"

int nbl_core_init(const struct nbl_adapter *adapter, const struct rte_eth_dev *eth_dev)
{
	RTE_SET_USED(adapter);
	RTE_SET_USED(eth_dev);

	return 0;
}

void nbl_core_remove(const struct nbl_adapter *adapter)
{
	RTE_SET_USED(adapter);
}

int nbl_core_start(const struct nbl_adapter *adapter)
{
	RTE_SET_USED(adapter);

	return 0;
}

void nbl_core_stop(const struct nbl_adapter *adapter)
{
	RTE_SET_USED(adapter);
}

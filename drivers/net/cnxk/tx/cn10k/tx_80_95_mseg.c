/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#include "cn10k_ethdev.h"
#include "cn10k_tx.h"

#define T(name, sz, flags)                                                     \
	NIX_TX_XMIT_MSEG(cn10k_nix_xmit_pkts_mseg_##name, sz, flags)

NIX_TX_FASTPATH_MODES_80_95
#undef T

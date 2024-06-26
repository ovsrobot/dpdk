/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */

#include "cn9k_ethdev.h"
#include "cn9k_tx.h"

#if !defined(CNXK_DIS_TMPLT_FUNC)

#define T(name, sz, flags)                                                     \
	NIX_TX_XMIT_VEC_MSEG(cn9k_nix_xmit_pkts_vec_mseg_##name, sz, flags)

NIX_TX_FASTPATH_MODES_112_127
#undef T

#endif

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */

#include "cn10k_rx.h"

#ifdef _ROC_API_H_
#error "roc_api.h is included"
#endif

#if !defined(CNXK_DIS_TMPLT_FUNC)

#define R(name, flags)                                                         \
	NIX_RX_RECV_VEC_MSEG(cn10k_nix_recv_pkts_vec_mseg_##name, flags)       \
	NIX_RX_RECV_VEC_MSEG(cn10k_nix_recv_pkts_reas_vec_mseg_##name,         \
			     flags | NIX_RX_REAS_F)

NIX_RX_FASTPATH_MODES_48_63
#undef R

#endif

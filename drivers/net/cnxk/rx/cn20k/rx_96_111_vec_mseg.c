/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2024 Marvell.
 */

#include "cn20k_rx.h"

#ifdef _ROC_API_H_
#error "roc_api.h is included"
#endif

#if !defined(CNXK_DIS_TMPLT_FUNC)

#define R(name, flags)                                                                             \
	NIX_RX_RECV_VEC_MSEG(cn20k_nix_recv_pkts_vec_mseg_##name, flags)                           \
	NIX_RX_RECV_VEC_MSEG(cn20k_nix_recv_pkts_reas_vec_mseg_##name, flags | NIX_RX_REAS_F)

NIX_RX_FASTPATH_MODES_96_111
#undef R

#endif

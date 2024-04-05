/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */

#include "cn9k_worker.h"
#include "cnxk_eventdev.h"
#include "cnxk_worker.h"

#if !defined(CNXK_DIS_TMPLT_FUNC)

#define R(name, flags)                                                         \
	SSO_CMN_DEQ_BURST(cn9k_sso_hws_dual_deq_tmo_seg_burst_##name,          \
			  cn9k_sso_hws_dual_deq_tmo_seg_##name, flags)

NIX_RX_FASTPATH_MODES_48_63
#undef R

#endif

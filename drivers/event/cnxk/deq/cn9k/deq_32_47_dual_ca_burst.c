/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#include "cn9k_worker.h"
#include "cnxk_eventdev.h"
#include "cnxk_worker.h"

#define R(name, flags)                                                         \
	SSO_CMN_DEQ_BURST(cn9k_sso_hws_dual_deq_ca_burst_##name,               \
			  cn9k_sso_hws_dual_deq_ca_##name, flags)

NIX_RX_FASTPATH_MODES_32_47
#undef R

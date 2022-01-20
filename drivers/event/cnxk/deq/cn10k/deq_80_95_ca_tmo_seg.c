/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#include "cn10k_worker.h"
#include "cnxk_eventdev.h"
#include "cnxk_worker.h"

#define R(name, flags)                                                         \
	SSO_DEQ_TMO_CA_SEG(cn10k_sso_hws_deq_tmo_ca_seg_##name, flags)

NIX_RX_FASTPATH_MODES_80_95
#undef R

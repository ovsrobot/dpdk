/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */

#include "cn10k_worker.h"

#ifdef _ROC_API_H_
#error "roc_api.h is included"
#endif

#if !defined(CNXK_DIS_TMPLT_FUNC)

#define R(name, flags)                                                         \
	SSO_DEQ(cn10k_sso_hws_deq_##name, flags)                               \
	SSO_DEQ(cn10k_sso_hws_reas_deq_##name, flags | NIX_RX_REAS_F)

NIX_RX_FASTPATH_MODES_64_79
#undef R

#endif

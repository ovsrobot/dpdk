/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#include "cn10k_worker.h"

#define T(name, sz, flags) SSO_TX(cn10k_sso_hws_tx_adptr_enq_##name, sz, flags)

NIX_TX_FASTPATH_MODES_80_95
#undef T

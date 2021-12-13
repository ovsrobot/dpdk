/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#include "cn9k_worker.h"
#include "cnxk_eventdev.h"
#include "cnxk_worker.h"

#define R(name, flags) SSO_DEQ_SEG(cn9k_sso_hws_deq_seg_##name, flags)

NIX_RX_FASTPATH_MODES_96_111
#undef R

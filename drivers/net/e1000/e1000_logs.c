/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Intel Corporation
 */

#include "e1000_logs.h"

RTE_LOG_REGISTER(e1000_logtype_init, .init, NOTICE)
RTE_LOG_REGISTER(e1000_logtype_driver, .driver, NOTICE)
#ifdef RTE_LIBRTE_E1000_DEBUG_RX
RTE_LOG_REGISTER(e1000_logtype_rx, .rx, DEBUG)
#endif
#ifdef RTE_LIBRTE_E1000_DEBUG_TX
RTE_LOG_REGISTER(e1000_logtype_tx, .tx, DEBUG)
#endif
#ifdef RTE_LIBRTE_E1000_DEBUG_TX_FREE
RTE_LOG_REGISTER(e1000_logtype_tx_free, .tx_free, DEBUG)
#endif

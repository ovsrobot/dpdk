/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 Yunsilicon Technology Co., Ltd.
 */

#include "xsc_log.h"

RTE_LOG_REGISTER_SUFFIX(xsc_logtype_init, init, NOTICE);
RTE_LOG_REGISTER_SUFFIX(xsc_logtype_driver, driver, NOTICE);
#ifdef RTE_ETHDEV_DEBUG_RX
RTE_LOG_REGISTER_SUFFIX(xsc_logtype_rx, rx, DEBUG);
#endif
#ifdef RTE_ETHDEV_DEBUG_TX
RTE_LOG_REGISTER_SUFFIX(xsc_logtype_tx, tx, DEBUG);
#endif

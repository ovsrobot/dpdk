/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _NTCONN_MODULES_H_
#define _NTCONN_MODULES_H_

#include "ntos_system.h"

/*
 * All defined NT connection modules
 */
int ntconn_adap_register(struct drv_s *drv);
int ntconn_stat_register(struct drv_s *drv);
int ntconn_flow_register(struct drv_s *drv);
int ntconn_meter_register(struct drv_s *drv);
int ntconn_test_register(struct drv_s *drv);

#endif /* _NTCONN_MODULES_H_ */

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */
#include "mp_crypto.h"
#include "mp_crypto_parser.h"

int			mp_app_driver_id;
/* Global driver id, one per mp_app */
int			mp_app_device_id;
/* For now we use only one device type, so for session
 * init only one need to be provided
 */
struct mp_app_dev	mp_app_devs[MP_APP_MAX_DEVS];
/* Global devices list */
uint16_t		mp_app_devs_cnt;
/* Global device counter */
uint8_t			mp_app_max_queues;
/* Per process queue counter */
const struct rte_memzone *mp_app_process_mz;
struct mp_app_process_data *mp_shared_data;
/* Data shared across processes
 * memzone name = MP_PROC_SHARED_MZ
 */

int mp_crypto_exit_flag;
/* Global exit flag */

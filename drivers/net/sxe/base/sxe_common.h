/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */
#ifndef __SXE_DPDK_COMMON_H__
#define __SXE_DPDK_COMMON_H__

u64 sxe_trace_id_gen(void);

void sxe_trace_id_clean(void);

u64 sxe_trace_id_get(void);

u64 sxe_time_get_real_ms(void);

#endif

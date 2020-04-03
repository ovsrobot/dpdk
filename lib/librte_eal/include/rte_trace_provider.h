/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell International Ltd.
 */

#ifndef _RTE_TRACE_H_
#error do not include this file directly, use <rte_trace.h> instead
#endif

#ifndef _RTE_TRACE_PROVIDER_H_
#define _RTE_TRACE_PROVIDER_H_

#define __RTE_TRACE_EVENT_HEADER_ID_SHIFT (48)

#define __RTE_TRACE_FIELD_ENABLE_MASK (1ULL << 63)
#define __RTE_TRACE_FIELD_ENABLE_DISCARD (1ULL << 62)
#define __RTE_TRACE_FIELD_SIZE_SHIFT 0
#define __RTE_TRACE_FIELD_SIZE_MASK (0xffffULL << __RTE_TRACE_FIELD_SIZE_SHIFT)
#define __RTE_TRACE_FIELD_ID_SHIFT (16)
#define __RTE_TRACE_FIELD_ID_MASK (0xffffULL << __RTE_TRACE_FIELD_ID_SHIFT)
#define __RTE_TRACE_FIELD_LEVEL_SHIFT (32)
#define __RTE_TRACE_FIELD_LEVEL_MASK (0xffULL << __RTE_TRACE_FIELD_LEVEL_SHIFT)


#endif /* _RTE_TRACE_PROVIDER_H_ */

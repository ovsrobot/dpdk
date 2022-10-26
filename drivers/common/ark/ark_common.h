/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Atomic Rules LLC
 */

#ifndef _ARK_COMMON_H_
#define _ARK_COMMON_H_

#include <inttypes.h>
#include <rte_log.h>

/* system camel case definition changed to upper case */
#define PRIU32 PRIu32
#define PRIU64 PRIu64

/* Atomic Rules vendor id */
#define AR_VENDOR_ID 0x1d6c

/*
 * This structure is used to statically define the capabilities
 * of supported devices.
 * Capabilities:
 *  rqpacing -
 * Some HW variants require that PCIe read-requests be correctly throttled.
 * This is called "rqpacing" and has to do with credit and flow control
 * on certain Arkville implementations.
 *  isvf -
 * Some HW variants support sr-iov virtual functions.
 */
struct ark_caps {
	bool rqpacing;
	bool isvf;
};
struct ark_dev_caps {
	uint32_t  device_id;
	struct ark_caps  caps;
};
#define SET_DEV_CAPS(id, rqp, vf)		\
	{id, {.rqpacing = rqp, .isvf = vf} }

/* Format specifiers for string data pairs */
#define ARK_SU32  "\n\t%-20s    %'20" PRIU32
#define ARK_SU64  "\n\t%-20s    %'20" PRIU64
#define ARK_SU64X "\n\t%-20s    %#20" PRIx64
#define ARK_SPTR  "\n\t%-20s    %20p"

extern int ark_common_logtype;
#define ARK_PMD_LOG(level, fmt, args...)	\
	rte_log(RTE_LOG_ ##level, ark_common_logtype, "ARK_COMMON: " fmt, ## args)

#endif

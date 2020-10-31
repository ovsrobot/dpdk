/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2016-2020 Intel Corporation
 */

#include "rte_memcpy.h"
#include "rte_io.h"

/* Inline functions required in more than one source file. */

static inline struct dlb_eventdev *
dlb_pmd_priv(const struct rte_eventdev *eventdev)
{
	return eventdev->data->dev_private;
}

static inline void
dlb_movntdq_single(void *dest, void *src)
{
	long long *_src  = (long long *)src;
	__m128i src_data0 = (__m128i){_src[0], _src[1]};

	_mm_stream_si128(dest, src_data0);
}

static inline void
dlb_cldemote(void *addr)
{
	/* Load addr into RSI, then demote the cache line of the address
	 * contained in that register.
	 */
	asm volatile(".byte 0x0f, 0x1c, 0x06" :: "S" (addr));
}

static inline void
dlb_movdir64b(void *dest, void *src)
{
	asm volatile(".byte 0x66, 0x0f, 0x38, 0xf8, 0x02"
		     :
		     : "a" (dest), "d" (src));
}

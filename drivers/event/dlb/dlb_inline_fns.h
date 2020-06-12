/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2016-2020 Intel Corporation
 */

#include "rte_memcpy.h"
#include "rte_io.h"

/* Inline functions required in more than one source file.
 */

static inline struct dlb_eventdev *
dlb_pmd_priv(const struct rte_eventdev *eventdev)
{
	return eventdev->data->dev_private;
}

static inline void
dlb_umonitor(volatile void *addr)
{
	asm volatile(".byte 0xf3, 0x0f, 0xae, 0xf7\t\n"
			:
			: "D" (addr));
}

static inline void
dlb_umwait(int state, uint64_t timeout)
{
	uint32_t eax = timeout & UINT32_MAX;
	uint32_t edx = timeout >> 32;

	asm volatile(".byte 0xf2, 0x0f, 0xae, 0xf7\t\n"
			:
			: "D" (state),  "a" (eax), "d" (edx));
}

static inline void
dlb_movntdq(struct dlb_enqueue_qe *qe4, uint64_t *pp_addr)
{
	/* Move entire 64B cache line of QEs, 128 bits (16B) at a time. */
	long long *_qe  = (long long *)qe4;
	__v2di src_data0 = (__v2di){_qe[0], _qe[1]};
	__v2di src_data1 = (__v2di){_qe[2], _qe[3]};
	__v2di src_data2 = (__v2di){_qe[4], _qe[5]};
	__v2di src_data3 = (__v2di){_qe[6], _qe[7]};

	__builtin_ia32_movntdq((__v2di *)pp_addr + 0, (__v2di)src_data0);
	rte_wmb();
	__builtin_ia32_movntdq((__v2di *)pp_addr + 1, (__v2di)src_data1);
	rte_wmb();
	__builtin_ia32_movntdq((__v2di *)pp_addr + 2, (__v2di)src_data2);
	rte_wmb();
	__builtin_ia32_movntdq((__v2di *)pp_addr + 3, (__v2di)src_data3);
	rte_wmb();
}

static inline void
dlb_movntdq_single(void *qe4, void *pp_addr)
{
	long long *_qe  = (long long *)qe4;
	__v2di src_data0 = (__v2di){_qe[0], _qe[1]};

	__builtin_ia32_movntdq((__v2di *)pp_addr, (__v2di)src_data0);
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
dlb_movdir64b(struct dlb_enqueue_qe *qe4, uint64_t *pp_addr)
{
	asm volatile(".byte 0x66, 0x0f, 0x38, 0xf8, 0x02"
		     :
		     : "a" (pp_addr), "d" (qe4));
}

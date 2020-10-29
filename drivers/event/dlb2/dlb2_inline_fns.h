/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2016-2020 Intel Corporation
 */

#ifndef _DLB2_INLINE_FNS_H_
#define _DLB2_INLINE_FNS_H_

/* Inline functions required in more than one source file. */

static inline struct dlb2_eventdev *
dlb2_pmd_priv(const struct rte_eventdev *eventdev)
{
	return eventdev->data->dev_private;
}

static inline void
dlb2_umonitor(volatile void *addr)
{
	asm volatile(".byte 0xf3, 0x0f, 0xae, 0xf7\t\n"
			:
			: "D" (addr));
}

static inline void
dlb2_umwait(int state, uint64_t timeout)
{
	uint32_t eax = timeout & UINT32_MAX;
	uint32_t edx = timeout >> 32;

	asm volatile(".byte 0xf2, 0x0f, 0xae, 0xf7\t\n"
			:
			: "D" (state),  "a" (eax), "d" (edx));
}

static inline void
dlb2_movntdq_single(void *pp_addr, void *qe4)
{
	long long *_qe  = (long long *)qe4;
	__v2di src_data0 = (__v2di){_qe[0], _qe[1]};

	__builtin_ia32_movntdq((__v2di *)pp_addr, (__v2di)src_data0);
}

static inline void
dlb2_cldemote(void *addr)
{
	/* Load addr into RSI, then demote the cache line of the address
	 * contained in that register.
	 */
	asm volatile(".byte 0x0f, 0x1c, 0x06" :: "S" (addr));
}

static inline void
dlb2_movdir64b(void *pp_addr, void *qe4)
{
	asm volatile(".byte 0x66, 0x0f, 0x38, 0xf8, 0x02"
		     :
		     : "a" (pp_addr), "d" (qe4));
}

#endif /* _DLB2_INLINE_FNS_H_ */

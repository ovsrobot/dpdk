/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.
 */

#ifndef _SSSNIC_MISC_H_
#define _SSSNIC_MISC_H_

#define SSSNIC_LOWER_32_BITS(x) ((uint32_t)(x))
#define SSSNIC_UPPER_32_BITS(x) ((uint32_t)(((x) >> 16) >> 16))

static inline void
sssnic_mem_cpu_to_be_32(void *in, void *out, int size)
{
	uint32_t i;
	uint32_t num;
	uint32_t *data_in = (uint32_t *)in;
	uint32_t *data_out = (uint32_t *)out;

	num = size / sizeof(uint32_t);

	for (i = 0; i < num; i++) {
		*data_out = rte_cpu_to_be_32(*data_in);
		data_in++;
		data_out++;
	}
}

static inline void
sssnic_mem_be_to_cpu_32(void *in, void *out, int size)
{
	uint32_t i;
	uint32_t num;
	uint32_t *data_in = (uint32_t *)in;
	uint32_t *data_out = (uint32_t *)out;

	num = size / sizeof(uint32_t);

	for (i = 0; i < num; i++) {
		*data_out = rte_be_to_cpu_32(*data_in);
		data_in++;
		data_out++;
	}
}

static inline bool
sssnic_is_zero_ipv6_addr(const void *ipv6_addr)
{
	const uint64_t *ddw = ipv6_addr;
	return ddw[0] == 0 && ddw[1] == 0;
}

#endif /* _SSSNIC_MISC_H_ */

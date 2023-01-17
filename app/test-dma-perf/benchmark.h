/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Intel Corporation
 */

#ifndef _BENCHMARK_H_
#define _BENCHMARK_H_

void dma_mem_copy_benchmark(struct test_configure *cfg);

void cpu_mem_copy_benchmark(struct test_configure *cfg);

#endif /* _BENCHMARK_H_ */

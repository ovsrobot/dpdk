/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) <2021> Intel Corporation
 */

#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <rte_per_lcore.h>
#include <rte_errno.h>
#include <rte_string_fns.h>
#include <rte_malloc.h>

#include "test.h"

static int
asan_heap_buffer_overflow(void)
{
	uint32_t malloc_size = 9;

	char *p = rte_zmalloc(NULL, malloc_size, 0);
	if (!p) {
		printf("rte_zmalloc error.");
		return -1;
	}
	p[9] = 'a';

	return 0;
}

REGISTER_TEST_COMMAND(asan_heap_buffer_overflow_autotest, asan_heap_buffer_overflow);

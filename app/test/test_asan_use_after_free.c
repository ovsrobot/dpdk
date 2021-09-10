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
asan_use_after_free(void)
{
	char *p = rte_zmalloc(NULL, 9, 0);
	if (!p) {
		printf("rte_zmalloc error.");
		return -1;
	}
	rte_free(p);
	*p = 'a';

	return 0;
}

REGISTER_TEST_COMMAND(asan_use_after_free_autotest, asan_use_after_free);

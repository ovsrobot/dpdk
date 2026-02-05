/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2025 Red Hat, Inc.
 */

#include <stdlib.h>
#include <rte_spinlock.h>
#include <rte_eal.h>

#include <eal_export.h>
#include "eal_private.h"

#define MAX_CLEANUP_CALLBACKS 16

static rte_eal_cleanup_callback_t cleanup_callbacks[MAX_CLEANUP_CALLBACKS];
static int num_cleanup_callbacks;
static rte_spinlock_t cleanup_lock = RTE_SPINLOCK_INITIALIZER;

RTE_EXPORT_SYMBOL(rte_eal_cleanup_register)
int
rte_eal_cleanup_register(rte_eal_cleanup_callback_t callback)
{
	int ret = -1;

	if (callback == NULL)
		return -1;

	rte_spinlock_lock(&cleanup_lock);
	if (num_cleanup_callbacks < MAX_CLEANUP_CALLBACKS) {
		cleanup_callbacks[num_cleanup_callbacks++] = callback;
		ret = 0;
	}
	rte_spinlock_unlock(&cleanup_lock);

	return ret;
}

void
eal_cleanup_callbacks_run(void)
{
	int i;

	rte_spinlock_lock(&cleanup_lock);
	for (i = 0; i < num_cleanup_callbacks; i++) {
		if (cleanup_callbacks[i] != NULL)
			cleanup_callbacks[i]();
	}
	rte_spinlock_unlock(&cleanup_lock);
}

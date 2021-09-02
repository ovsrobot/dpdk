/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 HiSilicon Limited.
 * Copyright(c) 2021 Intel Corporation.
 */

#include <rte_common.h>
#include <rte_dev.h>
#include <rte_dmadev.h>
#include <rte_bus_vdev.h>

#include "test.h"

/* from test_dmadev_api.c */
extern int test_dmadev_api(uint16_t dev_id);

static int
test_apis(void)
{
	const char *pmd = "dma_skeleton";
	int id;
	int ret;

	if (rte_vdev_init(pmd, NULL) < 0)
		return TEST_SKIPPED;
	id = rte_dmadev_get_dev_id(pmd);
	if (id < 0)
		return TEST_SKIPPED;
	printf("\n### Test dmadev infrastructure using skeleton driver\n");
	ret = test_dmadev_api(id);
	rte_vdev_uninit(pmd);

	return ret;
}

static int
test_dmadev(void)
{
	/* basic sanity on dmadev infrastructure */
	if (test_apis() < 0)
		return -1;

	return 0;
}

REGISTER_TEST_COMMAND(dmadev_autotest, test_dmadev);

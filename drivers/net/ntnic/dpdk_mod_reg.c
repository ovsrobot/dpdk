/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <rte_flow_driver.h>
#include "dpdk_mod_reg.h"

static struct sg_ops_s *sg_ops;

void register_sg_ops(struct sg_ops_s *ops)
{
	sg_ops = ops;
}

const struct sg_ops_s *get_sg_ops(void)
{
	return sg_ops;
}

/*
 *
 */
static struct meter_ops_s *meter_ops;

void register_meter_ops(struct meter_ops_s *ops)
{
	meter_ops = ops;
}

const struct meter_ops_s *get_meter_ops(void)
{
	return meter_ops;
}

/*
 *
 */
static const struct ntnic_filter_ops *ntnic_filter_ops;

void register_ntnic_filter_ops(const struct ntnic_filter_ops *ops)
{
	ntnic_filter_ops = ops;
}

const struct ntnic_filter_ops *get_ntnic_filter_ops(void)
{
	return ntnic_filter_ops;
}

/*
 *
 */
static struct ntnic_xstats_ops *ntnic_xstats_ops;

void register_ntnic_xstats_ops(struct ntnic_xstats_ops *ops)
{
	ntnic_xstats_ops = ops;
}

struct ntnic_xstats_ops *get_ntnic_xstats_ops(void)
{
	return ntnic_xstats_ops;
}

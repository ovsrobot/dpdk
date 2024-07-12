/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "ntnic_mod_reg.h"

static const struct adapter_ops *adapter_ops;

void register_adapter_ops(const struct adapter_ops *ops)
{
	adapter_ops = ops;
}

const struct adapter_ops *get_adapter_ops(void)
{
	if (adapter_ops == NULL)
		adapter_init();
	return adapter_ops;
}

static struct clk9563_ops *clk9563_ops;

void register_clk9563_ops(struct clk9563_ops *ops)
{
	clk9563_ops = ops;
}

struct clk9563_ops *get_clk9563_ops(void)
{
	if (clk9563_ops == NULL)
		clk9563_ops_init();
	return clk9563_ops;
}

static struct rst_nt200a0x_ops *rst_nt200a0x_ops;

void register_rst_nt200a0x_ops(struct rst_nt200a0x_ops *ops)
{
	rst_nt200a0x_ops = ops;
}

struct rst_nt200a0x_ops *get_rst_nt200a0x_ops(void)
{
	if (rst_nt200a0x_ops == NULL)
		rst_nt200a0x_ops_init();
	return rst_nt200a0x_ops;
}

static struct rst9563_ops *rst9563_ops;

void register_rst9563_ops(struct rst9563_ops *ops)
{
	rst9563_ops = ops;
}

struct rst9563_ops *get_rst9563_ops(void)
{
	if (rst9563_ops == NULL)
		rst9563_ops_init();
	return rst9563_ops;
}

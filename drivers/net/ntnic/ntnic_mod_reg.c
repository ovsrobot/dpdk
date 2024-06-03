/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <rte_flow_driver.h>
#include "ntnic_mod_reg.h"

/*
 *
 */
static struct link_ops_s *link_100g_ops;

void register_100g_link_ops(struct link_ops_s *ops)
{
	link_100g_ops = ops;
}

const struct link_ops_s *get_100g_link_ops(void)
{
	return link_100g_ops;
}

/*
 *
 */
static struct link_ops_s *link_agx_100g_ops;

void register_agx_100g_link_ops(struct link_ops_s *ops)
{
	link_agx_100g_ops = ops;
}

const struct link_ops_s *get_agx_100g_link_ops(void)
{
	return link_agx_100g_ops;
}

/*
 *
 */
static struct link_ops_s *link_25g_ops;

void register_25g_link_ops(struct link_ops_s *ops)
{
	link_25g_ops = ops;
}

const struct link_ops_s *get_25g_link_ops(void)
{
	return link_25g_ops;
}

/*
 *
 */
static struct link_ops_s *link_40g_ops;

void register_40g_link_ops(struct link_ops_s *ops)
{
	link_40g_ops = ops;
}

const struct link_ops_s *get_40g_link_ops(void)
{
	return link_40g_ops;
}

/*
 *
 */
static struct link_ops_s *link_8x10g_ops;

void register_8x10g_link_ops(struct link_ops_s *ops)
{
	link_8x10g_ops = ops;
}

const struct link_ops_s *get_8x10g_link_ops(void)
{
	return link_8x10g_ops;
}

/*
 *
 */
static struct avr_sensors_ops *avr_sensors_ops;

void register_avr_sensors_ops(struct avr_sensors_ops *ops)
{
	avr_sensors_ops = ops;
}

struct avr_sensors_ops *get_avr_sensors_ops(void)
{
	return avr_sensors_ops;
}

/*
 *
 */
static struct board_sensors_ops *board_sensors_ops;

void register_board_sensors_ops(struct board_sensors_ops *ops)
{
	board_sensors_ops = ops;
}

struct board_sensors_ops *get_board_sensors_ops(void)
{
	return board_sensors_ops;
}

/*
 *
 */
static struct ntavr_ops *ntavr_ops;

void register_ntavr_ops(struct ntavr_ops *ops)
{
	ntavr_ops = ops;
}

struct ntavr_ops *get_ntavr_ops(void)
{
	return ntavr_ops;
}

/*
 *
 */
static struct sensor_conversion_fun_ops *sensor_conversion_fun_ops;

void register_sensor_conversion_fun_ops(struct sensor_conversion_fun_ops *ops)
{
	sensor_conversion_fun_ops = ops;
}

struct sensor_conversion_fun_ops *get_sensor_conversion_fun_ops(void)
{
	return sensor_conversion_fun_ops;
}

/*
 *
 */
static struct sensor_ops *sensor_ops;

void register_sensor_ops(struct sensor_ops *ops)
{
	sensor_ops = ops;
}

struct sensor_ops *get_sensor_ops(void)
{
	return sensor_ops;
}

/*
 *
 */
static struct nim_sensors_ops *nim_sensors_ops;

void register_nim_sensors_ops(struct nim_sensors_ops *ops)
{
	nim_sensors_ops = ops;
}

struct nim_sensors_ops *get_nim_sensors_ops(void)
{
	return nim_sensors_ops;
}

/*
 *
 */
static const struct port_ops *port_ops;

void register_port_ops(const struct port_ops *ops)
{
	port_ops = ops;
}

const struct port_ops *get_port_ops(void)
{
	return port_ops;
}

/*
 *
 */
static const struct nt4ga_stat_ops *nt4ga_stat_ops;

void register_nt4ga_stat_ops(const struct nt4ga_stat_ops *ops)
{
	nt4ga_stat_ops = ops;
}

const struct nt4ga_stat_ops *get_nt4ga_stat_ops(void)
{
	return nt4ga_stat_ops;
}

/*
 *
 */
static const struct adapter_ops *adapter_ops;

void register_adapter_ops(const struct adapter_ops *ops)
{
	adapter_ops = ops;
}

const struct adapter_ops *get_adapter_ops(void)
{
	return adapter_ops;
}

static struct clk9530_ops *clk9530_ops;

void register_clk9530_ops(struct clk9530_ops *ops)
{
	clk9530_ops = ops;
}

struct clk9530_ops *get_clk9530_ops(void)
{
	return clk9530_ops;
}

static struct clk9544_ops *clk9544_ops;

void register_clk9544_ops(struct clk9544_ops *ops)
{
	clk9544_ops = ops;
}

struct clk9544_ops *get_clk9544_ops(void)
{
	return clk9544_ops;
}

static struct clk9563_ops *clk9563_ops;

void register_clk9563_ops(struct clk9563_ops *ops)
{
	clk9563_ops = ops;
}

struct clk9563_ops *get_clk9563_ops(void)
{
	return clk9563_ops;
}

static struct clk9572_ops *clk9572_ops;

void register_clk9572_ops(struct clk9572_ops *ops)
{
	clk9572_ops = ops;
}

struct clk9572_ops *get_clk9572_ops(void)
{
	return clk9572_ops;
}

static struct rst_nt200a0x_ops *rst_nt200a0x_ops;

void register_rst_nt200a0x_ops(struct rst_nt200a0x_ops *ops)
{
	rst_nt200a0x_ops = ops;
}

struct rst_nt200a0x_ops *get_rst_nt200a0x_ops(void)
{
	return rst_nt200a0x_ops;
}

static struct rst9530_ops *rst9530_ops;

void register_rst9530_ops(struct rst9530_ops *ops)
{
	rst9530_ops = ops;
}

struct rst9530_ops *get_rst9530_ops(void)
{
	return rst9530_ops;
}

static struct rst9544_ops *rst9544_ops;

void register_rst9544_ops(struct rst9544_ops *ops)
{
	rst9544_ops = ops;
}

struct rst9544_ops *get_rst9544_ops(void)
{
	return rst9544_ops;
}

static struct rst9563_ops *rst9563_ops;

void register_rst9563_ops(struct rst9563_ops *ops)
{
	rst9563_ops = ops;
}

struct rst9563_ops *get_rst9563_ops(void)
{
	return rst9563_ops;
}

static struct rst9572_ops *rst9572_ops;

void register_rst9572_ops(struct rst9572_ops *ops)
{
	rst9572_ops = ops;
}

struct rst9572_ops *get_rst9572_ops(void)
{
	return rst9572_ops;
}

static struct rst_nt400dxx_ops *rst_nt400dxx_ops;

void register_rst_nt400dxx_ops(struct rst_nt400dxx_ops *ops)
{
	rst_nt400dxx_ops = ops;
}

struct rst_nt400dxx_ops *get_rst_nt400dxx_ops(void)
{
	return rst_nt400dxx_ops;
}

/*
 *
 */
static const struct profile_inline_ops *profile_inline_ops;

void register_profile_inline_ops(const struct profile_inline_ops *ops)
{
	profile_inline_ops = ops;
}

const struct profile_inline_ops *get_profile_inline_ops(void)
{
	return profile_inline_ops;
}

/*
 *
 */
static const struct flow_filter_ops *flow_filter_ops;

void register_flow_filter_ops(const struct flow_filter_ops *ops)
{
	flow_filter_ops = ops;
}

const struct flow_filter_ops *get_flow_filter_ops(void)
{
	return flow_filter_ops;
}

/*
 *
 */
static const struct rte_flow_ops *dev_flow_ops;

void register_dev_flow_ops(const struct rte_flow_ops *ops)
{
	dev_flow_ops = ops;
}

const struct rte_flow_ops *get_dev_flow_ops(void)
{
	return dev_flow_ops;
}

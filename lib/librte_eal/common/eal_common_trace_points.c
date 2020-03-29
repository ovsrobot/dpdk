/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell International Ltd.
 */

#define RTE_TRACE_POINT_REGISTER_SELECT /* Select trace point register macros */

#include <rte_trace_eal.h>

RTE_TRACE_POINT_DEFINE(rte_trace_lib_eal_generic_void);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_eal_generic_u64);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_eal_generic_u32);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_eal_generic_u16);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_eal_generic_u8);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_eal_generic_i64);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_eal_generic_i32);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_eal_generic_i16);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_eal_generic_i8);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_eal_generic_int);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_eal_generic_long);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_eal_generic_float);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_eal_generic_double);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_eal_generic_ptr);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_eal_generic_str);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_eal_generic_func);

RTE_INIT(eal_trace_init)
{
	RTE_TRACE_POINT_REGISTER(rte_trace_lib_eal_generic_void,
				 lib.eal.generic.void, INFO);
	RTE_TRACE_POINT_REGISTER(rte_trace_lib_eal_generic_u64,
				 lib.eal.generic.u64, INFO);
	RTE_TRACE_POINT_REGISTER(rte_trace_lib_eal_generic_u32,
				 lib.eal.generic.u32, INFO);
	RTE_TRACE_POINT_REGISTER(rte_trace_lib_eal_generic_u16,
				 lib.eal.generic.u16, INFO);
	RTE_TRACE_POINT_REGISTER(rte_trace_lib_eal_generic_u8,
				 lib.eal.generic.u8, INFO);
	RTE_TRACE_POINT_REGISTER(rte_trace_lib_eal_generic_i64,
				 lib.eal.generic.i64, INFO);
	RTE_TRACE_POINT_REGISTER(rte_trace_lib_eal_generic_i32,
				 lib.eal.generic.i32, INFO);
	RTE_TRACE_POINT_REGISTER(rte_trace_lib_eal_generic_i16,
				 lib.eal.generic.i16, INFO);
	RTE_TRACE_POINT_REGISTER(rte_trace_lib_eal_generic_i8,
				 lib.eal.generic.i8, INFO);
	RTE_TRACE_POINT_REGISTER(rte_trace_lib_eal_generic_int,
				 lib.eal.generic.int, INFO);
	RTE_TRACE_POINT_REGISTER(rte_trace_lib_eal_generic_long,
				 lib.eal.generic.long, INFO);
	RTE_TRACE_POINT_REGISTER(rte_trace_lib_eal_generic_float,
				 lib.eal.generic.float, INFO);
	RTE_TRACE_POINT_REGISTER(rte_trace_lib_eal_generic_double,
				 lib.eal.generic.double, INFO);
	RTE_TRACE_POINT_REGISTER(rte_trace_lib_eal_generic_ptr,
				 lib.eal.generic.ptr, INFO);
	RTE_TRACE_POINT_REGISTER(rte_trace_lib_eal_generic_str,
				 lib.eal.generic.string, INFO);
	RTE_TRACE_POINT_REGISTER(rte_trace_lib_eal_generic_func,
				 lib.eal.generic.func, INFO);
}

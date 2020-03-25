/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell International Ltd.
 */

#ifndef _RTE_TRACE_EAL_H_
#define _RTE_TRACE_EAL_H_

/**
 * @file
 *
 * API for EAL trace support
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_alarm.h>
#include <rte_interrupts.h>
#include <rte_trace.h>

/* Generic */
RTE_TRACE_POINT(
	rte_trace_lib_eal_generic_void,
	RTE_TRACE_POINT_ARGS(void),
)

RTE_TRACE_POINT(
	rte_trace_lib_eal_generic_u64,
	RTE_TRACE_POINT_ARGS(uint64_t in),
	rte_trace_ctf_u64(in);
)

RTE_TRACE_POINT(
	rte_trace_lib_eal_generic_u32,
	RTE_TRACE_POINT_ARGS(uint32_t in),
	rte_trace_ctf_u32(in);
)

RTE_TRACE_POINT(
	rte_trace_lib_eal_generic_u16,
	RTE_TRACE_POINT_ARGS(uint16_t in),
	rte_trace_ctf_u16(in);
)

RTE_TRACE_POINT(
	rte_trace_lib_eal_generic_u8,
	RTE_TRACE_POINT_ARGS(uint8_t in),
	rte_trace_ctf_u8(in);
)

RTE_TRACE_POINT(
	rte_trace_lib_eal_generic_i64,
	RTE_TRACE_POINT_ARGS(int64_t in),
	rte_trace_ctf_i64(in);
)

RTE_TRACE_POINT(
	rte_trace_lib_eal_generic_i32,
	RTE_TRACE_POINT_ARGS(int32_t in),
	rte_trace_ctf_i32(in);
)

RTE_TRACE_POINT(
	rte_trace_lib_eal_generic_i16,
	RTE_TRACE_POINT_ARGS(int16_t in),
	rte_trace_ctf_i16(in);
)

RTE_TRACE_POINT(
	rte_trace_lib_eal_generic_i8,
	RTE_TRACE_POINT_ARGS(int8_t in),
	rte_trace_ctf_i8(in);
)

RTE_TRACE_POINT(
	rte_trace_lib_eal_generic_int,
	RTE_TRACE_POINT_ARGS(int in),
	rte_trace_ctf_int(in);
)

RTE_TRACE_POINT(
	rte_trace_lib_eal_generic_long,
	RTE_TRACE_POINT_ARGS(long in),
	rte_trace_ctf_long(in);
)

RTE_TRACE_POINT(
	rte_trace_lib_eal_generic_float,
	RTE_TRACE_POINT_ARGS(float in),
	rte_trace_ctf_float(in);
)

RTE_TRACE_POINT(
	rte_trace_lib_eal_generic_double,
	RTE_TRACE_POINT_ARGS(double in),
	rte_trace_ctf_double(in);
)

RTE_TRACE_POINT(
	rte_trace_lib_eal_generic_ptr,
	RTE_TRACE_POINT_ARGS(const void *ptr),
	rte_trace_ctf_ptr(ptr);
)

RTE_TRACE_POINT(
	rte_trace_lib_eal_generic_str,
	RTE_TRACE_POINT_ARGS(const char *str),
	rte_trace_ctf_string(str);
)

RTE_TRACE_POINT(
	rte_trace_lib_eal_generic_func,
	RTE_TRACE_POINT_ARGS(const char *func),
	rte_trace_ctf_string(func);
)

#define RTE_TRACE_LIB_EAL_GENERIC_FUNC rte_trace_lib_eal_generic_func(__func__)

/* Alarm */
RTE_TRACE_POINT(
	rte_trace_lib_eal_alarm_set,
	RTE_TRACE_POINT_ARGS(uint64_t us, rte_eal_alarm_callback cb_fn,
			     void *cb_arg, int rc),
	rte_trace_ctf_u64(us); rte_trace_ctf_ptr(cb_fn);
	rte_trace_ctf_ptr(cb_arg); rte_trace_ctf_int(rc);
)

RTE_TRACE_POINT(
	rte_trace_lib_eal_alarm_cancel,
	RTE_TRACE_POINT_ARGS(rte_eal_alarm_callback cb_fn, void *cb_arg,
			     int count),
	rte_trace_ctf_ptr(cb_fn); rte_trace_ctf_ptr(cb_arg);
	rte_trace_ctf_int(count);
)

/* Memory */
RTE_TRACE_POINT(
	rte_trace_lib_eal_mem_zmalloc,
	RTE_TRACE_POINT_ARGS(const char *type, size_t size, unsigned int align,
			     int socket, void *ptr),
	rte_trace_ctf_string(type); rte_trace_ctf_long(size);
	rte_trace_ctf_u32(align); rte_trace_ctf_int(socket);
	rte_trace_ctf_ptr(ptr);
)

RTE_TRACE_POINT(
	rte_trace_lib_eal_mem_malloc,
	RTE_TRACE_POINT_ARGS(const char *type, size_t size, unsigned int align,
			     int socket, void *ptr),
	rte_trace_ctf_string(type); rte_trace_ctf_long(size);
	rte_trace_ctf_u32(align); rte_trace_ctf_int(socket);
	rte_trace_ctf_ptr(ptr);
)

RTE_TRACE_POINT(
	rte_trace_lib_eal_mem_realloc,
	RTE_TRACE_POINT_ARGS(size_t size, unsigned int align,
			     int socket, void *ptr),
	rte_trace_ctf_long(size); rte_trace_ctf_u32(align);
	rte_trace_ctf_int(socket); rte_trace_ctf_ptr(ptr);
)

RTE_TRACE_POINT(
	rte_trace_lib_eal_mem_free,
	RTE_TRACE_POINT_ARGS(void *ptr),
	rte_trace_ctf_ptr(ptr);
)

/* Memzone */
RTE_TRACE_POINT(
	rte_trace_lib_eal_memzone_reserve,
	RTE_TRACE_POINT_ARGS(const char *name, size_t len, int socket_id,
			     unsigned int flags, unsigned int align,
			     unsigned int bound, const void *mz),
	rte_trace_ctf_string(name); rte_trace_ctf_long(len);
	rte_trace_ctf_int(socket_id); rte_trace_ctf_u32(flags);
	rte_trace_ctf_u32(align); rte_trace_ctf_u32(bound);
	rte_trace_ctf_ptr(mz);
)

RTE_TRACE_POINT(
	rte_trace_lib_eal_memzone_lookup,
	RTE_TRACE_POINT_ARGS(const char *name, const void *memzone),
	rte_trace_ctf_string(name); rte_trace_ctf_ptr(memzone);
)

RTE_TRACE_POINT(
	rte_trace_lib_eal_memzone_free,
	RTE_TRACE_POINT_ARGS(const char *name, void *addr, int rc),
	rte_trace_ctf_string(name); rte_trace_ctf_ptr(addr);
	rte_trace_ctf_int(rc);
)

/* Thread */
RTE_TRACE_POINT(
	rte_trace_lib_eal_thread_remote_launch,
	RTE_TRACE_POINT_ARGS(int (*f)(void *), void *arg,
			     unsigned int slave_id, int rc),
	rte_trace_ctf_ptr(f); rte_trace_ctf_ptr(arg);
	rte_trace_ctf_u32(slave_id); rte_trace_ctf_int(rc);
)
RTE_TRACE_POINT(
	rte_trace_lib_eal_thread_lcore_ready,
	RTE_TRACE_POINT_ARGS(unsigned int lcore_id, const char *cpuset),
	rte_trace_ctf_u32(lcore_id); rte_trace_ctf_string(cpuset);
)

/* Interrupt */
RTE_TRACE_POINT(
	rte_trace_lib_eal_intr_callback_register,
	RTE_TRACE_POINT_ARGS(const struct rte_intr_handle *handle,
			     rte_intr_callback_fn cb, void *cb_arg, int rc),
	rte_trace_ctf_int(rc); rte_trace_ctf_int(handle->vfio_dev_fd);
	rte_trace_ctf_int(handle->fd); rte_trace_ctf_int(handle->type);
	rte_trace_ctf_u32(handle->max_intr); rte_trace_ctf_u32(handle->nb_efd);
	rte_trace_ctf_ptr(cb); rte_trace_ctf_ptr(cb_arg);
)
RTE_TRACE_POINT(
	rte_trace_lib_eal_intr_callback_unregister,
	RTE_TRACE_POINT_ARGS(const struct rte_intr_handle *handle,
			     rte_intr_callback_fn cb, void *cb_arg, int rc),
	rte_trace_ctf_int(rc); rte_trace_ctf_int(handle->vfio_dev_fd);
	rte_trace_ctf_int(handle->fd); rte_trace_ctf_int(handle->type);
	rte_trace_ctf_u32(handle->max_intr); rte_trace_ctf_u32(handle->nb_efd);
	rte_trace_ctf_ptr(cb); rte_trace_ctf_ptr(cb_arg);
)
RTE_TRACE_POINT(
	rte_trace_lib_eal_intr_enable,
	RTE_TRACE_POINT_ARGS(const struct rte_intr_handle *handle, int rc),
	rte_trace_ctf_int(rc); rte_trace_ctf_int(handle->vfio_dev_fd);
	rte_trace_ctf_int(handle->fd); rte_trace_ctf_int(handle->type);
	rte_trace_ctf_u32(handle->max_intr); rte_trace_ctf_u32(handle->nb_efd);
)
RTE_TRACE_POINT(
	rte_trace_lib_eal_intr_disable,
	RTE_TRACE_POINT_ARGS(const struct rte_intr_handle *handle, int rc),
	rte_trace_ctf_int(rc); rte_trace_ctf_int(handle->vfio_dev_fd);
	rte_trace_ctf_int(handle->fd); rte_trace_ctf_int(handle->type);
	rte_trace_ctf_u32(handle->max_intr); rte_trace_ctf_u32(handle->nb_efd);
)

#ifdef __cplusplus
}
#endif

#endif /* _RTE_TRACE_EAL_H_ */

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell International Ltd.
 */

#ifndef __EAL_TRACE_H
#define __EAL_TRACE_H

#include <rte_spinlock.h>
#include <rte_trace.h>
#include <rte_uuid.h>

#define trace_err(fmt, args...)\
	RTE_LOG(ERR, EAL, "%s():%u " fmt "\n",\
		__func__, __LINE__, ## args)

#define trace_crit(fmt, args...)\
	RTE_LOG(CRIT, EAL, "%s():%u " fmt "\n",\
		__func__, __LINE__, ## args)

#define TRACE_PREFIX_LEN 12
#define TRACE_DIR_STR_LEN (sizeof("YYYY-mm-dd-AM-HH-MM-SS") + TRACE_PREFIX_LEN)
#define TRACE_CTF_FIELD_SIZE 384
#define TRACE_POINT_NAME_SIZE 64

struct trace_point {
	STAILQ_ENTRY(trace_point) next;
	rte_trace_t *handle;
	char name[TRACE_POINT_NAME_SIZE];
	char ctf_field[TRACE_CTF_FIELD_SIZE];
};

struct trace {
	char dir[PATH_MAX];
	int dir_offset;
	int register_errno;
	bool global_status;
	enum rte_trace_mode mode;
	rte_uuid_t uuid;
	uint32_t level;
	uint32_t nb_trace_points;
	rte_spinlock_t lock;
};

/* Helper functions */
static inline uint16_t
trace_id_get(rte_trace_t *trace)
{
	return (*trace & __RTE_TRACE_FIELD_ID_MASK) >>
		__RTE_TRACE_FIELD_ID_SHIFT;
}

/* Trace object functions */
struct trace *trace_obj_get(void);

/* Trace point list functions */
STAILQ_HEAD(trace_point_head, trace_point);
struct trace_point_head *trace_list_head_get(void);

/* Util functions */
bool trace_has_duplicate_entry(void);
void trace_uuid_generate(void);
int trace_mkdir(void);

/* EAL interface */
int eal_trace_init(void);
void eal_trace_fini(void);

#endif /* __EAL_TRACE_H */

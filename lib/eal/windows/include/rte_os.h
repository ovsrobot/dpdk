/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2019 Intel Corporation
 */

#ifndef _RTE_OS_H_
#define _RTE_OS_H_

/**
 * This header should contain any definition
 * which is not supported natively or named differently in Windows.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef QUEUE_MACRO_DEBUG_TRACE
/* Store the last 2 places the queue element or head was altered */
struct qm_trace {
	unsigned long	 lastline;
	unsigned long	 prevline;
	const char	*lastfile;
	const char	*prevfile;
};

/**
 * These macros are compatible with the sys/queue.h provided
 * at DPDK source code.
 */
#define	TRACEBUF	struct qm_trace trace;
#define	TRACEBUF_INITIALIZER	{ __LINE__, 0, __FILE__, NULL } ,

#define	QMD_TRACE_HEAD(head) do {					\
	(head)->trace.prevline = (head)->trace.lastline;		\
	(head)->trace.prevfile = (head)->trace.lastfile;		\
	(head)->trace.lastline = __LINE__;				\
	(head)->trace.lastfile = __FILE__;				\
} while (0)

#define	QMD_TRACE_ELEM(elem) do {					\
	(elem)->trace.prevline = (elem)->trace.lastline;		\
	(elem)->trace.prevfile = (elem)->trace.lastfile;		\
	(elem)->trace.lastline = __LINE__;				\
	(elem)->trace.lastfile = __FILE__;				\
} while (0)

#else	/* !QUEUE_MACRO_DEBUG_TRACE */
#define	QMD_TRACE_ELEM(elem)
#define	QMD_TRACE_HEAD(head)
#define	TRACEBUF
#define	TRACEBUF_INITIALIZER
#endif	/* QUEUE_MACRO_DEBUG_TRACE */

#ifdef QUEUE_MACRO_DEBUG_TRASH
#define	QMD_SAVELINK(name, link)	void **name = (void *)&(link)
#define	TRASHIT(x)		do {(x) = (void *)-1;} while (0)
#define	QMD_IS_TRASHED(x)	((x) == (void *)(intptr_t)-1)
#else	/* !QUEUE_MACRO_DEBUG_TRASH */
#define	QMD_SAVELINK(name, link)
#define	TRASHIT(x)
#define	QMD_IS_TRASHED(x)	0
#endif	/* QUEUE_MACRO_DEBUG_TRASH */

#define	QMD_TAILQ_CHECK_HEAD(head, field)
#define	QMD_TAILQ_CHECK_TAIL(head, headname)
#define	QMD_TAILQ_CHECK_NEXT(elm, field)
#define	QMD_TAILQ_CHECK_PREV(elm, field)


#define	RTE_TAILQ_EMPTY(head)	((head)->tqh_first == NULL)

#define	RTE_TAILQ_FIRST(head)	((head)->tqh_first)

#define	RTE_TAILQ_INIT(head) do {					\
	RTE_TAILQ_FIRST((head)) = NULL;					\
	(head)->tqh_last = &RTE_TAILQ_FIRST((head));			\
	QMD_TRACE_HEAD(head);						\
} while (0)

#define	RTE_TAILQ_HEAD(name, type)					\
struct name {								\
	struct type *tqh_first;	/* first element */			\
	struct type **tqh_last;	/* addr of last next element */		\
	TRACEBUF							\
}
#define	RTE_TAILQ_HEAD_INITIALIZER(head)				\
	{ NULL, &(head).tqh_first, TRACEBUF_INITIALIZER }

#define	RTE_TAILQ_ENTRY(type)						\
struct {								\
	struct type *tqe_next;	/* next element */			\
	struct type **tqe_prev;	/* address of previous next element */	\
	TRACEBUF							\
}

#define	RTE_TAILQ_NEXT(elm, field) ((elm)->field.tqe_next)
#define	RTE_TAILQ_LAST(head, headname)					\
	(*(((struct headname *)((head)->tqh_last))->tqh_last))

#define	RTE_TAILQ_FOREACH(var, head, field)				\
	for ((var) = RTE_TAILQ_FIRST((head));				\
	    (var);							\
	    (var) = RTE_TAILQ_NEXT((var), field))

#define	RTE_TAILQ_INSERT_TAIL(head, elm, field) do {			\
	QMD_TAILQ_CHECK_TAIL(head, field);				\
	RTE_TAILQ_NEXT((elm), field) = NULL;				\
	(elm)->field.tqe_prev = (head)->tqh_last;			\
	*(head)->tqh_last = (elm);					\
	(head)->tqh_last = &RTE_TAILQ_NEXT((elm), field);		\
	QMD_TRACE_HEAD(head);						\
	QMD_TRACE_ELEM(&(elm)->field);					\
} while (0)

#define	RTE_TAILQ_REMOVE(head, elm, field) do {				\
	QMD_SAVELINK(oldnext, (elm)->field.tqe_next);			\
	QMD_SAVELINK(oldprev, (elm)->field.tqe_prev);			\
	QMD_TAILQ_CHECK_NEXT(elm, field);				\
	QMD_TAILQ_CHECK_PREV(elm, field);				\
	if ((RTE_TAILQ_NEXT((elm), field)) != NULL)			\
		RTE_TAILQ_NEXT((elm), field)->field.tqe_prev = 		\
		    (elm)->field.tqe_prev;				\
	else {								\
		(head)->tqh_last = (elm)->field.tqe_prev;		\
		QMD_TRACE_HEAD(head);					\
	}								\
	*(elm)->field.tqe_prev = RTE_TAILQ_NEXT((elm), field);		\
	TRASHIT(*oldnext);						\
	TRASHIT(*oldprev);						\
	QMD_TRACE_ELEM(&(elm)->field);					\
} while (0)

#define RTE_TAILQ_INSERT_BEFORE(listelm, elm, field) \
	TAILQ_INSERT_BEFORE(listelm, elm, field)
#define RTE_TAILQ_INSERT_AFTER(head, listelm, elm, field) \
	TAILQ_INSERT_AFTER(head, listelm, elm, field)
#define RTE_TAILQ_INSERT_HEAD(head, elm, field) \
	TAILQ_INSERT_HEAD(head, elm, field)


#define	RTE_STAILQ_HEAD(name, type)					\
struct name {								\
	struct type *stqh_first;/* first element */			\
	struct type **stqh_last;/* addr of last next element */		\
}
#define	RTE_STAILQ_HEAD_INITIALIZER(head)				\
	{ NULL, &(head).stqh_first }

#define	RTE_STAILQ_ENTRY(type)						\
struct {								\
	struct type *stqe_next;	/* next element */			\
}


/* cpu_set macros implementation */
#define RTE_CPU_AND(dst, src1, src2) CPU_AND(dst, src1, src2)
#define RTE_CPU_OR(dst, src1, src2) CPU_OR(dst, src1, src2)
#define RTE_CPU_FILL(set) CPU_FILL(set)
#define RTE_CPU_NOT(dst, src) CPU_NOT(dst, src)

/* This is an exception without "rte_" prefix, because Windows does have
 * ssize_t, but it's defined in <windows.h> which we avoid to expose.
 * If ssize_t is defined in user code, it necessarily has the same type.
 */
typedef long long ssize_t;

#ifdef __cplusplus
}
#endif

#endif /* _RTE_OS_H_ */

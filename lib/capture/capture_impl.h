/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Stephen Hemminger
 */
#ifndef CAPTURE_IMPL_H
#define CAPTURE_IMPL_H

#define RTE_LOGTYPE_CAPTURE rte_capture_logtype
extern int rte_capture_logtype;
#define CAPTURE_LOG(level, ...) \
	RTE_LOG_LINE_PREFIX(level, CAPTURE, "%s(): ", __func__, __VA_ARGS__)

struct rte_capture_filter;

#ifdef RTE_HAS_LIBPCAP
struct rte_capture_filter *__rte_capture_filter_create(const char *str);
const char *__rte_capture_filter_string(struct rte_capture_filter *filter);
void __rte_capture_filter_free(struct rte_capture_filter *filter);
uint64_t __rte_capture_filter(const struct rte_capture_filter *filter, struct rte_mbuf *mb);

#else /* !RTE_HAS_LIBPCAP */

/* Stub version if pcap is not available */
static inline struct rte_capture_filter *
__rte_capture_filter_create(const char *str)
{
	RTE_SET_USED(str);
	return NULL; /* not supported */
}

static inline const char *
__rte_capture_filter_string(struct rte_capture_filter *filter)
{
	RTE_SET_USED(filter);
	return NULL;
}

static inline void
__rte_capture_filter_free(struct rte_capture_filter *filter)
{
	RTE_SET_USED(filter);
}

/*
 * This will  be zero if the packet doesn't match the filter and non-zero if
 * the packet matches the filter.
 */
static inline uint64_t
__rte_capture_filter(const struct rte_capture_filter *filter, struct rte_mbuf *mb)
{
	RTE_SET_USED(filter);
	RTE_SET_USED(mb);
	return 1;
}

#endif  /* !RTE_HAS_LIBPCAP */
#endif /* CAPTURE_IMPL_H */

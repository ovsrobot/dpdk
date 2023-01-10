/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell International Ltd.
 */

#ifndef _RTE_GRAPH_PCAP_TRACE_H_
#define _RTE_GRAPH_PCAP_TRACE_H_

/**
 * @file rte_graph_pcap_trace.h
 *
 * @warning
 * @b EXPERIMENTAL:
 * All functions in this file may be changed or removed without prior notice.
 *
 * This API enables to capture packet at each node with mbuf and node metadata.
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Pcap trace enable/disable function.
 *
 * The function is called to enable/disable graph pcap trace functionality.
 *
 * @param val
 *   Value to be set to enable/disable graph pcap trace.
 */
__rte_experimental
void rte_pcap_trace_enable(int val);

/**
 * Check graph pcap trace is enable/disable.
 *
 * The function is called to check if the graph pcap trace is enabled/disabled.
 *
 * @return
 *   - 1: Enable
 *   - 0: Disable
 */
__rte_experimental
int rte_pcap_trace_is_enable(void);

/**
 * Initialise graph pcap trace functionality.
 *
 * The function invoked when the graph pcap trace is enabled from the
 * application.
 *
 */
__rte_experimental
void rte_graph_pcap_trace_init(void);

/**
 * Pcap trace set number of packets to capture.
 *
 * The function is called to configure total number of packets to be captured.
 *
 * @param val
 *   Number of packets to capture.
 */
__rte_experimental
void rte_num_pkt_to_capture(uint64_t val);

/**
 * Pcap trace file name to capture packets.
 *
 * The function is called to configure file name to capture packets in.
 *
 * @param filename
 *   Number of packets to capture.
 */
__rte_experimental
void rte_filename_to_capture_pkt(const char *filename);

/**
 * Exit graph pcap trace functionality.
 *
 * The function is called to exit graph pcap trace and close open fd's.
 */
__rte_experimental
void rte_graph_pcap_trace_exit(void);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_GRAPH_PCAP_TRACE_H_ */

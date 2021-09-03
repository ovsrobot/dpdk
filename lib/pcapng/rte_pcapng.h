/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Microsoft Corporation
 */

/**
 * @file
 * RTE pcapng
 *
 * @warning
 * @b EXPERIMENTAL:
 * All functions in this file may be changed or removed without prior notice.
 *
 * Pcapng is an evolution from the pcap format, created to address some of
 * its deficiencies. Namely, the lack of extensibility and inability to store
 * additional information.
 *
 * For details about the file format see RFC:
 *   https://www.ietf.org/id/draft-tuexen-opsawg-pcapng-03.html
 *  and
 *    https://github.com/pcapng/pcapng/
 */

#ifndef _RTE_PCAPNG_H_
#define _RTE_PCAPNG_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize the pcapng library.
 *
 * Computes the time offset for timestamps.
 *
 * @return
 *    0 on success, -1 on error
 */
__rte_experimental
int rte_pcapng_init(void);

/* Opaque handle used for functions in this library. */
typedef struct rte_pcapng rte_pcapng_t;

/**
 * Write data to existing open file
 *
 * @param fd
 *   file descriptor
 * @param osname
 *   Optional description of the operting system.
 *   Examples: "Debian 11", "Windows Server 22"
 * @param hardware
 *   Optional description of the hardware used to create this file.
 *   Examples: "x86 Virtual Machine"
 * @param appname
 *   Optional: application name recorded in the pcapng file.
 *   Example: "dpdk-dumpcap 1.0 (DPDK 20.11)"
 * @param comment
 *   Optional comment to add to file header.
 * @return
 *   handle to library, or NULL in case of error (and rte_errno is set).
 */
__rte_experimental
rte_pcapng_t *
rte_pcapng_fdopen(int fd,
		  const char *osname, const char *hardware,
		  const char *appname, const char *comment);

/**
 * Close capture file
 *
 * @param self
 *  handle to library
 */
__rte_experimental
void
rte_pcapng_close(rte_pcapng_t *self);

/**
 * Direction flag
 * These should match Enhanced Packet Block flag bits
 */
enum rte_pcapng_direction {
	RTE_PCAPNG_DIRECTION_UNKNOWN = 0,
	RTE_PCAPNG_DIRECTION_IN  = 1,
	RTE_PCAPNG_DIRECTION_OUT = 2,
};

/**
 * Format an mbuf for writing to file
 *
 * @param port_id
 *   The Ethernet port on which packet was receive
 *   or is going to be transmitted.
 * @param queue
 *   The queue on the Ethernet port.
 * @param mp
 *   The mempool from which the "clone" mbufs are allocated.
 * @param m
 *   The mbuf to copy
 * @param length
 *   The upper limit on bytes to copy.  Passing UINT32_MAX
 *   means all data (after offset).
 * @param timestamp
 *   The timestamp in TSC cycles.
 * @param direction
 *   The direction of the packer: receive, transmit or unknown.
 *
 * @return
 *   - The pointer to the new mbuf formatted for pcapng_write
 *   - NULL if allocation fails.
 *
 */
__rte_experimental
struct rte_mbuf *
rte_pcapng_copy(uint16_t port_id, uint16_t queue,
		const struct rte_mbuf *m, struct rte_mempool *mp,
		uint32_t length, uint64_t timestamp,
		enum rte_pcapng_direction direction);

/**
 * Write packets to the capture file.
 *
 * Packets to be captured are copied by rte_pcapng_mbuf()
 * and then this function is called to write them to the file.
 * @warning
 * Do not pass original mbufs
 *
 * @param self
 *  The handle to the packet capture file
 * @param pkts
 *  The address of an array of *nb_pkts* pointers to *rte_mbuf* structures
 *  which contain the output packets
 * @param nb_pkts
 *  The number of packets to write to the file.
 * @return
 *  The number of bytes written to file, -1 on failure to write file.
 *  The mbuf's in *pkts* are always freed.
 */
__rte_experimental
ssize_t
rte_pcapng_write_packets(rte_pcapng_t *self,
			 struct rte_mbuf *pkts[], uint16_t nb_pkts);

/**
 * Write an Interface statistics block.
 * For statistics, use 0 if don't know or care to report it.
 * Should be called before closing capture to report results.
 *
 * @param self
 *  The handle to the packet capture file
 * @param port
 *  The Ethernet port to report stats on.
 * @param received
 *  The number of packets received since the start of capturing.
 * @param missed
 *  The number of packets missed by the device.
 * @param accepted
 *  The number of packets accepted by the filter.
 * @param dropped
 *  The number of packets dropped by the application (OS)
 * @return
 *  number of bytes written to file, -1 on failure to write file
 */
__rte_experimental
int
rte_pcapng_write_stats(rte_pcapng_t *self, uint16_t port,
		       uint64_t received, uint64_t missed,
		       uint64_t accepted, uint64_t dropped);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_PCAPNG_H_ */

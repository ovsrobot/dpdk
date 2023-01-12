/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell International Ltd.
 */

#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>

#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_pcapng.h>

#include "rte_graph_worker.h"
#include "graph_private.h"

#define GRAPH_PCAP_BUF_SZ	128
#define GRAPH_PCAP_NUM_PACKETS	1024
#define GRAPH_PCAP_FILE_NAME_SZ	128
#define GRAPH_PCAP_FILE_NAME	"/tmp/graph_pcap_capture.pcapng"

static char file_name[GRAPH_PCAP_FILE_NAME_SZ];
static uint32_t pkt_buf_sz = RTE_MBUF_DEFAULT_BUF_SIZE;
static uint64_t packet_to_capture = GRAPH_PCAP_NUM_PACKETS;
static rte_pcapng_t *pcapng_fd;
static struct rte_mempool *mp;
static uint16_t port_id;
static uint64_t packet_captured[RTE_MAX_LCORE];
static int pcap_trace_enable;

void
rte_num_pkt_to_capture(uint64_t val)
{
	packet_to_capture = val;
}

void
rte_pcap_trace_enable(int val)
{
	pcap_trace_enable = val;
}

int
rte_pcap_trace_is_enable(void)
{
	return pcap_trace_enable;
}

void
rte_filename_to_capture_pkt(const char *filename)
{
	if (filename[0] == '\0')
		rte_strscpy(file_name, GRAPH_PCAP_FILE_NAME,
			    GRAPH_PCAP_FILE_NAME_SZ);
	else
		rte_strscpy(file_name, filename, GRAPH_PCAP_FILE_NAME_SZ);
}

void
rte_graph_pcap_trace_exit(void)
{
	rte_pcapng_close(pcapng_fd);
}

int
rte_graph_pcap_trace_init(void)
{
	int fd;

	port_id = rte_eth_find_next(0);
	if (port_id >= RTE_MAX_ETHPORTS) {
		fprintf(stderr, "No valid Ether port\n");
		return -1;
	}

	if (file_name[0] == '\0')
		rte_strscpy(file_name, GRAPH_PCAP_FILE_NAME,
			    GRAPH_PCAP_FILE_NAME_SZ);

	fd = open(file_name, O_CREAT | O_TRUNC | O_WRONLY, 0664);
	if (fd < 0) {
		perror("pcap file open failure");
		return -1;
	}

	fprintf(stdout, "pcapng: output file %s\n", file_name);

	/* open a test capture file */
	pcapng_fd = rte_pcapng_fdopen(fd, NULL, NULL, "Graph pcap tracer", NULL);
	if (pcapng_fd == NULL) {
		fprintf(stderr, "Graph rte_pcapng_fdopen failed\n");
		close(fd);
		return -1;
	}

	/* Make a pool for cloned packets */
	mp = rte_pktmbuf_pool_create_by_ops("pcapng_graph_pool",
			IOV_MAX + RTE_GRAPH_BURST_SIZE,
			0, 0, rte_pcapng_mbuf_size(pkt_buf_sz),
			SOCKET_ID_ANY, "ring_mp_sc");
	if (mp == NULL) {
		fprintf(stderr, "Cannot create mempool for graph pcap capture\n");
		rte_pcapng_close(pcapng_fd);
		return -1;
	}

	return 0;
}

uint16_t
rte_graph_pcap_trace_dispatch(struct rte_graph *graph,
			      struct rte_node *node, void **objs,
			      uint16_t nb_objs)
{
	uint64_t i, num_packets;
	struct rte_mbuf *mbuf_clones[RTE_GRAPH_BURST_SIZE];
	char buffer[GRAPH_PCAP_BUF_SZ];
	struct rte_mbuf *mbuf;
	ssize_t len;
	uint16_t gid = graph->id;

	if (!nb_objs || (packet_captured[gid] >= packet_to_capture))
		goto done;

	num_packets = packet_to_capture - packet_captured[gid];
	/* nb_objs will never be greater than RTE_GRAPH_BURST_SIZE */
	if (num_packets > nb_objs)
		num_packets = nb_objs;

	rte_strlcpy(buffer, node->name, GRAPH_PCAP_BUF_SZ);

	for (i = 0; i < num_packets; i++) {
		struct rte_mbuf *mc;
		mbuf = (struct rte_mbuf *)objs[i];

		mc = rte_pcapng_copy(port_id, 0, mbuf, mp, mbuf->pkt_len,
				     rte_get_tsc_cycles(), 0, buffer);
		if (mc == NULL)
			break;

		mbuf_clones[i] = mc;
	}

	/* write it to capture file */
	len = rte_pcapng_write_packets(pcapng_fd, mbuf_clones, i);
	rte_pktmbuf_free_bulk(mbuf_clones, i);
	if (len <= 0)
		goto done;

	packet_captured[gid] += i;

done:
	return node->original_process(graph, node, objs, nb_objs);
}

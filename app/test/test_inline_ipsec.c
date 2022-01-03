/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */


#include <stdio.h>
#include <inttypes.h>
#include <signal.h>
#include <unistd.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_security.h>
#include <rte_ipsec.h>
#include <rte_byteorder.h>
#include <rte_atomic.h>
#include <rte_malloc.h>
#include "test_inline_ipsec_reassembly_vectors.h"
#include "test.h"

#define NB_ETHPORTS_USED                (1)
#define NB_SOCKETS                      (2)
#define MEMPOOL_CACHE_SIZE 32
#define MAX_PKT_BURST                   (32)
#define RTE_TEST_RX_DESC_DEFAULT        (1024)
#define RTE_TEST_TX_DESC_DEFAULT        (1024)
#define RTE_PORT_ALL            (~(uint16_t)0x0)

/*
 * RX and TX Prefetch, Host, and Write-back threshold values should be
 * carefully set for optimal performance. Consult the network
 * controller's datasheet and supporting DPDK documentation for guidance
 * on how these parameters should be set.
 */
#define RX_PTHRESH 8 /**< Default values of RX prefetch threshold reg. */
#define RX_HTHRESH 8 /**< Default values of RX host threshold reg. */
#define RX_WTHRESH 0 /**< Default values of RX write-back threshold reg. */

#define TX_PTHRESH 32 /**< Default values of TX prefetch threshold reg. */
#define TX_HTHRESH 0  /**< Default values of TX host threshold reg. */
#define TX_WTHRESH 0  /**< Default values of TX write-back threshold reg. */

#define MAX_TRAFFIC_BURST              2048

#define NB_MBUF 1024

#define APP_REASS_TIMEOUT		20

static struct rte_mempool *mbufpool[NB_SOCKETS];
static struct rte_mempool *sess_pool[NB_SOCKETS];
static struct rte_mempool *sess_priv_pool[NB_SOCKETS];
/* ethernet addresses of ports */
static struct rte_ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

static struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode = RTE_ETH_MQ_RX_NONE,
		.split_hdr_size = 0,
		.offloads = RTE_ETH_RX_OFFLOAD_IP_REASSEMBLY |
			    RTE_ETH_RX_OFFLOAD_CHECKSUM |
			    RTE_ETH_RX_OFFLOAD_SECURITY,
	},
	.txmode = {
		.mq_mode = RTE_ETH_MQ_TX_NONE,
		.offloads = RTE_ETH_TX_OFFLOAD_SECURITY |
			    RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE,
	},
	.lpbk_mode = 1,  /* enable loopback */
};

static struct rte_eth_rxconf rx_conf = {
	.rx_thresh = {
		.pthresh = RX_PTHRESH,
		.hthresh = RX_HTHRESH,
		.wthresh = RX_WTHRESH,
	},
	.rx_free_thresh = 32,
};

static struct rte_eth_txconf tx_conf = {
	.tx_thresh = {
		.pthresh = TX_PTHRESH,
		.hthresh = TX_HTHRESH,
		.wthresh = TX_WTHRESH,
	},
	.tx_free_thresh = 32, /* Use PMD default values */
	.tx_rs_thresh = 32, /* Use PMD default values */
};

enum {
	LCORE_INVALID = 0,
	LCORE_AVAIL,
	LCORE_USED,
};

struct lcore_cfg {
	uint8_t status;
	uint8_t socketid;
	uint16_t nb_ports;
	uint16_t port;
} __rte_cache_aligned;

struct lcore_cfg lcore_cfg;

static uint64_t link_mbps;

/* Create Inline IPsec session */
static int
create_inline_ipsec_session(struct ipsec_session_data *sa,
		uint16_t portid, struct rte_ipsec_session *ips,
		enum rte_security_ipsec_sa_direction dir,
		enum rte_security_ipsec_tunnel_type tun_type)
{
	int32_t ret = 0;
	struct rte_security_ctx *sec_ctx;
	uint32_t src_v4 = rte_cpu_to_be_32(RTE_IPV4(192, 168, 1, 0));
	uint32_t dst_v4 = rte_cpu_to_be_32(RTE_IPV4(192, 168, 1, 1));
	uint16_t src_v6[8] = {0x2607, 0xf8b0, 0x400c, 0x0c03, 0x0000, 0x0000,
				0x0000, 0x001a};
	uint16_t dst_v6[8] = {0x2001, 0x0470, 0xe5bf, 0xdead, 0x4957, 0x2174,
				0xe82c, 0x4887};
	struct rte_security_session_conf sess_conf = {
		.action_type = RTE_SECURITY_ACTION_TYPE_INLINE_PROTOCOL,
		.protocol = RTE_SECURITY_PROTOCOL_IPSEC,
		.ipsec = sa->ipsec_xform,
		.crypto_xform = &sa->xform.aead,
		.userdata = NULL,
	};
	sess_conf.ipsec.direction = dir;

	const struct rte_security_capability *sec_cap;

	sec_ctx = (struct rte_security_ctx *)
			rte_eth_dev_get_sec_ctx(portid);

	if (sec_ctx == NULL) {
		printf("Ethernet device doesn't support security features.\n");
		return TEST_SKIPPED;
	}

	sess_conf.crypto_xform->aead.key.data = sa->key.data;

	/* Save SA as userdata for the security session. When
	 * the packet is received, this userdata will be
	 * retrieved using the metadata from the packet.
	 *
	 * The PMD is expected to set similar metadata for other
	 * operations, like rte_eth_event, which are tied to
	 * security session. In such cases, the userdata could
	 * be obtained to uniquely identify the security
	 * parameters denoted.
	 */

	sess_conf.userdata = (void *) sa;
	sess_conf.ipsec.tunnel.type = tun_type;
	if (tun_type == RTE_SECURITY_IPSEC_TUNNEL_IPV4) {
		memcpy(&sess_conf.ipsec.tunnel.ipv4.src_ip, &src_v4,
				sizeof(src_v4));
		memcpy(&sess_conf.ipsec.tunnel.ipv4.dst_ip, &dst_v4,
				sizeof(dst_v4));
	} else {
		memcpy(&sess_conf.ipsec.tunnel.ipv6.src_addr, &src_v6,
				sizeof(src_v6));
		memcpy(&sess_conf.ipsec.tunnel.ipv6.dst_addr, &dst_v6,
				sizeof(dst_v6));
	}
	ips->security.ses = rte_security_session_create(sec_ctx,
				&sess_conf, sess_pool[lcore_cfg.socketid],
				sess_priv_pool[lcore_cfg.socketid]);
	if (ips->security.ses == NULL) {
		printf("SEC Session init failed: err: %d\n", ret);
		return TEST_FAILED;
	}

	sec_cap = rte_security_capabilities_get(sec_ctx);
	if (sec_cap == NULL) {
		printf("No capabilities registered\n");
		return TEST_SKIPPED;
	}

	/* iterate until ESP tunnel*/
	while (sec_cap->action !=
			RTE_SECURITY_ACTION_TYPE_NONE) {
		if (sec_cap->action == sess_conf.action_type &&
		    sec_cap->protocol ==
			RTE_SECURITY_PROTOCOL_IPSEC &&
		    sec_cap->ipsec.mode ==
			sess_conf.ipsec.mode &&
		    sec_cap->ipsec.direction == dir)
			break;
		sec_cap++;
	}

	if (sec_cap->action == RTE_SECURITY_ACTION_TYPE_NONE) {
		printf("No suitable security capability found\n");
		return TEST_SKIPPED;
	}

	ips->security.ol_flags = sec_cap->ol_flags;
	ips->security.ctx = sec_ctx;

	return 0;
}

/* Check the link status of all ports in up to 3s, and print them finally */
static void
check_all_ports_link_status(uint16_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 30 /* 3s (30 * 100ms) in total */
	uint16_t portid;
	uint8_t count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;
	int ret;
	char link_status[RTE_ETH_LINK_MAX_STR_LEN];

	printf("Checking link statuses...\n");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		for (portid = 0; portid < port_num; portid++) {
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			ret = rte_eth_link_get_nowait(portid, &link);
			if (ret < 0) {
				all_ports_up = 0;
				if (print_flag == 1)
					printf("Port %u link get failed: %s\n",
						portid, rte_strerror(-ret));
				continue;
			}

			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status && link_mbps == 0)
					link_mbps = link.link_speed;

				rte_eth_link_to_str(link_status,
					sizeof(link_status), &link);
				printf("Port %d %s\n", portid, link_status);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == RTE_ETH_LINK_DOWN) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1))
			print_flag = 1;
	}
}

static void
print_ethaddr(const char *name, const struct rte_ether_addr *eth_addr)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];
	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s%s", name, buf);
}

static void
copy_buf_to_pkt_segs(void *buf, unsigned len, struct rte_mbuf *pkt,
		unsigned offset)
{
	struct rte_mbuf *seg;
	void *seg_buf;
	unsigned copy_len;

	seg = pkt;
	while (offset >= seg->data_len) {
		offset -= seg->data_len;
		seg = seg->next;
	}
	copy_len = seg->data_len - offset;
	seg_buf = rte_pktmbuf_mtod_offset(seg, char *, offset);
	while (len > copy_len) {
		rte_memcpy(seg_buf, buf, (size_t) copy_len);
		len -= copy_len;
		buf = ((char *) buf + copy_len);
		seg = seg->next;
		seg_buf = rte_pktmbuf_mtod(seg, void *);
	}
	rte_memcpy(seg_buf, buf, (size_t) len);
}

static inline void
copy_buf_to_pkt(void *buf, unsigned len, struct rte_mbuf *pkt, unsigned offset)
{
	if (offset + len <= pkt->data_len) {
		rte_memcpy(rte_pktmbuf_mtod_offset(pkt, char *, offset), buf,
			   (size_t) len);
		return;
	}
	copy_buf_to_pkt_segs(buf, len, pkt, offset);
}

static inline int
init_traffic(struct rte_mempool *mp,
	     struct rte_mbuf **pkts_burst,
	     struct ipsec_test_packet *vectors[],
	     uint32_t nb_pkts)
{
	struct rte_mbuf *pkt;
	uint32_t i;

	for (i = 0; i < nb_pkts; i++) {
		pkt = rte_pktmbuf_alloc(mp);
		if (pkt == NULL) {
			return TEST_FAILED;
		}
		pkt->data_len = vectors[i]->len;
		pkt->pkt_len = vectors[i]->len;
		copy_buf_to_pkt(vectors[i]->data, vectors[i]->len,
				pkt, vectors[i]->l2_offset);

		pkts_burst[i] = pkt;
	}
	return i;
}

static int
init_lcore(void)
{
	unsigned lcore_id;

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		lcore_cfg.socketid =
			rte_lcore_to_socket_id(lcore_id);
		if (rte_lcore_is_enabled(lcore_id) == 0) {
			lcore_cfg.status = LCORE_INVALID;
			continue;
		} else {
			lcore_cfg.status = LCORE_AVAIL;
			break;
		}
	}
	return 0;
}

static int
init_mempools(unsigned nb_mbuf)
{
	struct rte_security_ctx *sec_ctx;
	int socketid;
	unsigned lcore_id;
	uint16_t nb_sess = 64;
	uint32_t sess_sz;
	char s[64];

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;

		socketid = rte_lcore_to_socket_id(lcore_id);
		if (socketid >= NB_SOCKETS) {
			rte_exit(EXIT_FAILURE,
				"Socket %d of lcore %u is out of range %d\n",
				socketid, lcore_id, NB_SOCKETS);
		}
		if (mbufpool[socketid] == NULL) {
			snprintf(s, sizeof(s), "mbuf_pool_%d", socketid);
			mbufpool[socketid] =
				rte_pktmbuf_pool_create(s, nb_mbuf,
					MEMPOOL_CACHE_SIZE, 0,
					RTE_MBUF_DEFAULT_BUF_SIZE, socketid);
			if (mbufpool[socketid] == NULL)
				rte_exit(EXIT_FAILURE,
					"Cannot init mbuf pool on socket %d\n",
					socketid);
			else
				printf("Allocated mbuf pool on socket %d\n",
					socketid);
		}

		sec_ctx = rte_eth_dev_get_sec_ctx(lcore_cfg.port);
		if (sec_ctx == NULL)
			continue;

		sess_sz = rte_security_session_get_size(sec_ctx);
		if (sess_pool[socketid] == NULL) {
			snprintf(s, sizeof(s), "sess_pool_%d", socketid);
			sess_pool[socketid] =
				rte_mempool_create(s, nb_sess,
					sess_sz,
					MEMPOOL_CACHE_SIZE, 0,
					NULL, NULL, NULL, NULL,
					socketid, 0);
			if (sess_pool[socketid] == NULL) {
				printf("Cannot init sess pool on socket %d\n",
					socketid);
				return TEST_FAILED;
			} else
				printf("Allocated sess pool on socket %d\n",
					socketid);
		}
		if (sess_priv_pool[socketid] == NULL) {
			snprintf(s, sizeof(s), "sess_priv_pool_%d", socketid);
			sess_priv_pool[socketid] =
				rte_mempool_create(s, nb_sess,
					sess_sz,
					MEMPOOL_CACHE_SIZE, 0,
					NULL, NULL, NULL, NULL,
					socketid, 0);
			if (sess_priv_pool[socketid] == NULL) {
				printf("Cannot init sess_priv pool on socket %d\n",
					socketid);
				return TEST_FAILED;
			} else
				printf("Allocated sess_priv pool on socket %d\n",
					socketid);
		}
	}
	return 0;
}

static void
create_default_flow(uint16_t port_id)
{
	struct rte_flow_action action[2];
	struct rte_flow_item pattern[2];
	struct rte_flow_attr attr = {0};
	struct rte_flow_error err;
	struct rte_flow *flow;
	int ret;

	/* Add the default rte_flow to enable SECURITY for all ESP packets */

	pattern[0].type = RTE_FLOW_ITEM_TYPE_ESP;
	pattern[0].spec = NULL;
	pattern[0].mask = NULL;
	pattern[0].last = NULL;
	pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

	action[0].type = RTE_FLOW_ACTION_TYPE_SECURITY;
	action[0].conf = NULL;
	action[1].type = RTE_FLOW_ACTION_TYPE_END;
	action[1].conf = NULL;

	attr.ingress = 1;

	ret = rte_flow_validate(port_id, &attr, pattern, action, &err);
	if (ret)
		return;

	flow = rte_flow_create(port_id, &attr, pattern, action, &err);
	if (flow == NULL)
		return;
}

struct rte_mbuf **tx_pkts_burst;

static int
compare_pkt_data(struct rte_mbuf *m, uint8_t *ref, unsigned int tot_len)
{
	unsigned int len;
	unsigned int nb_segs = m->nb_segs;
	unsigned int matched = 0;

	while (m && nb_segs != 0) {
		len = tot_len;
		if (len > m->data_len)
			len = m->data_len;
		if (len != 0) {
			if (memcmp(rte_pktmbuf_mtod(m, char *),
					ref + matched, len)) {
				printf("\n====Reassembly case failed: Data Mismatch");
				rte_hexdump(stdout, "Reassembled",
					rte_pktmbuf_mtod(m, char *),
					len);
				rte_hexdump(stdout, "reference",
					ref + matched,
					len);
				return TEST_FAILED;
			}
		}
		tot_len -= len;
		matched += len;
		m = m->next;
		nb_segs--;
	}
	return TEST_SUCCESS;
}

static int
test_reassembly(struct reassembly_vector *vector,
		enum rte_security_ipsec_tunnel_type tun_type)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	unsigned i, portid, nb_rx = 0, nb_tx = 0;
	struct rte_ipsec_session out_ips = {0};
	struct rte_ipsec_session in_ips = {0};
	struct rte_eth_dev_info dev_info = {0};
	int ret = 0;

	/* Initialize mbuf with test vectors. */
	nb_tx = reass_test_vectors_init(vector);

	portid = lcore_cfg.port;
	rte_eth_dev_info_get(portid, &dev_info);
	if (dev_info.reass_capa.max_frags < nb_tx)
		return TEST_SKIPPED;

	/**
	 * Set some finite value in timeout incase PMD support much
	 * more than requied in this app.
	 */
	if (dev_info.reass_capa.reass_timeout > APP_REASS_TIMEOUT) {
		dev_info.reass_capa.reass_timeout = APP_REASS_TIMEOUT;
		rte_eth_ip_reassembly_conf_set(portid, &dev_info.reass_capa);
	}

	init_traffic(mbufpool[lcore_cfg.socketid],
			tx_pkts_burst, vector->frags, nb_tx);

	/* Create Inline IPsec outbound session. */
	ret = create_inline_ipsec_session(vector->sa_data, portid, &out_ips,
			RTE_SECURITY_IPSEC_SA_DIR_EGRESS, tun_type);
	if (ret)
		return ret;
	for (i = 0; i < nb_tx; i++) {
		if (out_ips.security.ol_flags &
				RTE_SECURITY_TX_OLOAD_NEED_MDATA)
			rte_security_set_pkt_metadata(out_ips.security.ctx,
				out_ips.security.ses, tx_pkts_burst[i], NULL);
		tx_pkts_burst[i]->ol_flags |= RTE_MBUF_F_TX_SEC_OFFLOAD;
		tx_pkts_burst[i]->l2_len = RTE_ETHER_HDR_LEN;
	}
	/* Create Inline IPsec inbound session. */
	create_inline_ipsec_session(vector->sa_data, portid, &in_ips,
			RTE_SECURITY_IPSEC_SA_DIR_INGRESS, tun_type);
	create_default_flow(portid);

	nb_tx = rte_eth_tx_burst(portid, 0, tx_pkts_burst, nb_tx);

	rte_pause();

	do {
		nb_rx = rte_eth_rx_burst(portid, 0, pkts_burst, MAX_PKT_BURST);
		for (i = 0; i < nb_rx; i++) {
			if ((pkts_burst[i]->ol_flags &
			    RTE_MBUF_F_RX_IPREASSEMBLY_INCOMPLETE) &&
			    rte_eth_ip_reass_dynfield_is_registered()) {
				rte_eth_ip_reass_dynfield_t *dynfield[MAX_PKT_BURST];
				int j = 0;

				dynfield[j] = rte_eth_ip_reass_dynfield(pkts_burst[i]);
				while ((dynfield[j]->next_frag->ol_flags &
				    RTE_MBUF_F_RX_IPREASSEMBLY_INCOMPLETE) &&
				    dynfield[j]->nb_frags > 0) {

					rte_pktmbuf_dump(stdout,
						dynfield[j]->next_frag,
						dynfield[j]->next_frag->data_len);
					j++;
					dynfield[j] = rte_eth_ip_reass_dynfield(
						dynfield[j-1]->next_frag);
				}
				/**
				 * IP reassembly offload is incomplete, and
				 * fragments are listed in dynfield which
				 * can be reassembled in SW.
				 */
				printf("\nHW IP Reassembly failed,"
					"\nAttempt SW IP Reassembly,"
					"\nmbuf is chained with fragments.\n");
			}
		}
	} while (nb_rx == 0);

	/* Clear session data. */
	rte_security_session_destroy(out_ips.security.ctx,
				     out_ips.security.ses);
	rte_security_session_destroy(in_ips.security.ctx,
				     in_ips.security.ses);

	/* Compare results with known vectors. */
	if (nb_rx == 1) {
		if (vector->full_pkt->len == pkts_burst[0]->pkt_len)
			return compare_pkt_data(pkts_burst[0],
					vector->full_pkt->data,
					vector->full_pkt->len);
		else {
			rte_pktmbuf_dump(stdout, pkts_burst[0],
					pkts_burst[0]->pkt_len);
		}
	}

	return TEST_FAILED;
}

static int
test_ipsec(struct reassembly_vector *vector,
	   enum rte_security_ipsec_sa_direction dir,
	   enum rte_security_ipsec_tunnel_type tun_type)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	unsigned i, portid, nb_rx = 0, nb_tx = 1;
	struct rte_ipsec_session ips = {0};
	struct rte_eth_dev_info dev_info = {0};

	portid = lcore_cfg.port;
	rte_eth_dev_info_get(portid, &dev_info);
	if (dev_info.reass_capa.max_frags < nb_tx)
		return TEST_SKIPPED;

	init_traffic(mbufpool[lcore_cfg.socketid],
			tx_pkts_burst, vector->frags, nb_tx);

	/* Create Inline IPsec session. */
	if (create_inline_ipsec_session(vector->sa_data, portid, &ips, dir,
					tun_type))
		return TEST_FAILED;
	if (dir == RTE_SECURITY_IPSEC_SA_DIR_INGRESS)
		create_default_flow(portid);
	else {
		for (i = 0; i < nb_tx; i++) {
			if (ips.security.ol_flags &
					RTE_SECURITY_TX_OLOAD_NEED_MDATA)
				rte_security_set_pkt_metadata(ips.security.ctx,
				ips.security.ses, tx_pkts_burst[i], NULL);
			tx_pkts_burst[i]->ol_flags |= RTE_MBUF_F_TX_SEC_OFFLOAD;
			tx_pkts_burst[i]->l2_len = 14;
		}
	}

	nb_tx = rte_eth_tx_burst(portid, 0, tx_pkts_burst, nb_tx);

	rte_pause();

	do {
		nb_rx = rte_eth_rx_burst(portid, 0, pkts_burst, MAX_PKT_BURST);
	} while (nb_rx == 0);

	/* Destroy session so that other cases can create the session again */
	rte_security_session_destroy(ips.security.ctx, ips.security.ses);

	/* Compare results with known vectors. */
	if (nb_rx == 1) {
		if (memcmp(rte_pktmbuf_mtod(pkts_burst[0], char *),
					vector->full_pkt->data,
					(size_t) vector->full_pkt->len)) {
			printf("\n====Inline IPsec case failed: Data Mismatch");
			rte_hexdump(stdout, "received",
				rte_pktmbuf_mtod(pkts_burst[0], char *),
				vector->full_pkt->len);
			rte_hexdump(stdout, "reference",
				vector->full_pkt->data,
				vector->full_pkt->len);
			return TEST_FAILED;
		}
		return TEST_SUCCESS;
	} else
		return TEST_FAILED;
}

static int
ut_setup_inline_ipsec(void)
{
	uint16_t portid = lcore_cfg.port;
	int ret;

	/* Set IP reassembly configuration. */
	struct rte_eth_dev_info dev_info = {0};
	rte_eth_dev_info_get(portid, &dev_info);

	ret = rte_eth_ip_reassembly_conf_set(portid, &dev_info.reass_capa);
	if (ret < 0) {
		printf("IP reassembly configuration err=%d, port=%d\n",
			ret, portid);
		return ret;
	}

	/* Start device */
	ret = rte_eth_dev_start(portid);
	if (ret < 0) {
		printf("rte_eth_dev_start: err=%d, port=%d\n",
			ret, portid);
		return ret;
	}
	/* always eanble promiscuous */
	ret = rte_eth_promiscuous_enable(portid);
	if (ret != 0) {
		printf("rte_eth_promiscuous_enable: err=%s, port=%d\n",
			rte_strerror(-ret), portid);
		return ret;
	}
	lcore_cfg.port = portid;
	check_all_ports_link_status(1, RTE_PORT_ALL);

	return 0;
}

static void
ut_teardown_inline_ipsec(void)
{
	uint16_t portid = lcore_cfg.port;
	int socketid = lcore_cfg.socketid;
	int ret;

	/* port tear down */
	RTE_ETH_FOREACH_DEV(portid) {
		if (socketid != rte_eth_dev_socket_id(portid))
			continue;

		ret = rte_eth_dev_stop(portid);
		if (ret != 0)
			printf("rte_eth_dev_stop: err=%s, port=%u\n",
			       rte_strerror(-ret), portid);
	}
}

static int
testsuite_setup(void)
{
	uint16_t nb_rxd;
	uint16_t nb_txd;
	uint16_t nb_ports;
	int socketid, ret;
	uint16_t nb_rx_queue = 1, nb_tx_queue = 1;
	uint16_t portid = lcore_cfg.port;

	printf("Start inline IPsec test.\n");

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports < NB_ETHPORTS_USED) {
		printf("At least %u port(s) used for test\n",
		       NB_ETHPORTS_USED);
		return -1;
	}

	init_lcore();

	init_mempools(NB_MBUF);

	socketid = lcore_cfg.socketid;
	if (tx_pkts_burst == NULL) {
		tx_pkts_burst = (struct rte_mbuf **)
			rte_calloc_socket("tx_buff",
					  MAX_TRAFFIC_BURST * nb_ports,
					  sizeof(void *),
					  RTE_CACHE_LINE_SIZE, socketid);
		if (!tx_pkts_burst)
			return -1;
	}

	printf("Generate %d packets @socket %d\n",
	       MAX_TRAFFIC_BURST * nb_ports, socketid);

	nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
	nb_txd = RTE_TEST_TX_DESC_DEFAULT;

	/* port configure */
	ret = rte_eth_dev_configure(portid, nb_rx_queue,
				    nb_tx_queue, &port_conf);
	if (ret < 0) {
		printf("Cannot configure device: err=%d, port=%d\n",
			 ret, portid);
		return ret;
	}
	ret = rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);
	if (ret < 0) {
		printf("Cannot get mac address: err=%d, port=%d\n",
			 ret, portid);
		return ret;
	}
	printf("Port %u ", portid);
	print_ethaddr("Address:", &ports_eth_addr[portid]);
	printf("\n");

	/* tx queue setup */
	ret = rte_eth_tx_queue_setup(portid, 0, nb_txd,
				     socketid, &tx_conf);
	if (ret < 0) {
		printf("rte_eth_tx_queue_setup: err=%d, port=%d\n",
				ret, portid);
		return ret;
	}
	/* rx queue steup */
	ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd,
					socketid, &rx_conf,
					mbufpool[socketid]);
	if (ret < 0) {
		printf("rte_eth_rx_queue_setup: err=%d, port=%d\n",
				ret, portid);
		return ret;
	}


	return 0;
}

static void
testsuite_teardown(void)
{
	int ret;
	uint16_t portid = lcore_cfg.port;
	uint16_t socketid = lcore_cfg.socketid;

	/* port tear down */
	RTE_ETH_FOREACH_DEV(portid) {
		if (socketid != rte_eth_dev_socket_id(portid))
			continue;

		ret = rte_eth_dev_stop(portid);
		if (ret != 0)
			printf("rte_eth_dev_stop: err=%s, port=%u\n",
			       rte_strerror(-ret), portid);
	}
}
static int
test_ipsec_ipv4_encap_nofrag(void) {
	struct reassembly_vector ipv4_nofrag_case = {
				.sa_data = &conf_aes_128_gcm,
				.full_pkt = &pkt_ipv4_gcm128_cipher,
				.frags[0] = &pkt_ipv4_plain,
	};
	return test_ipsec(&ipv4_nofrag_case,
			RTE_SECURITY_IPSEC_SA_DIR_EGRESS,
			RTE_SECURITY_IPSEC_TUNNEL_IPV4);
}

static int
test_ipsec_ipv4_decap_nofrag(void) {
	struct reassembly_vector ipv4_nofrag_case = {
				.sa_data = &conf_aes_128_gcm,
				.full_pkt = &pkt_ipv4_plain,
				.frags[0] = &pkt_ipv4_gcm128_cipher,
	};
	return test_ipsec(&ipv4_nofrag_case,
			RTE_SECURITY_IPSEC_SA_DIR_INGRESS,
			RTE_SECURITY_IPSEC_TUNNEL_IPV4);
}

static int
test_reassembly_ipv4_nofrag(void) {
	struct reassembly_vector ipv4_nofrag_case = {
				.sa_data = &conf_aes_128_gcm,
				.full_pkt = &pkt_ipv4_plain,
				.frags[0] = &pkt_ipv4_plain,
	};
	return test_reassembly(&ipv4_nofrag_case,
			RTE_SECURITY_IPSEC_TUNNEL_IPV4);
}

static int
test_reassembly_ipv4_2frag(void) {
	struct reassembly_vector ipv4_2frag_case = {
				.sa_data = &conf_aes_128_gcm,
				.full_pkt = &pkt_ipv4_udp_p1,
				.frags[0] = &pkt_ipv4_udp_p1_f1,
				.frags[1] = &pkt_ipv4_udp_p1_f2,

	};
	return test_reassembly(&ipv4_2frag_case,
			RTE_SECURITY_IPSEC_TUNNEL_IPV4);
}

static int
test_reassembly_ipv6_2frag(void) {
	struct reassembly_vector ipv6_2frag_case = {
				.sa_data = &conf_aes_128_gcm,
				.full_pkt = &pkt_ipv6_udp_p1,
				.frags[0] = &pkt_ipv6_udp_p1_f1,
				.frags[1] = &pkt_ipv6_udp_p1_f2,
	};
	return test_reassembly(&ipv6_2frag_case,
			RTE_SECURITY_IPSEC_TUNNEL_IPV6);
}

static int
test_reassembly_ipv4_4frag(void) {
	struct reassembly_vector ipv4_4frag_case = {
				.sa_data = &conf_aes_128_gcm,
				.full_pkt = &pkt_ipv4_udp_p2,
				.frags[0] = &pkt_ipv4_udp_p2_f1,
				.frags[1] = &pkt_ipv4_udp_p2_f2,
				.frags[2] = &pkt_ipv4_udp_p2_f3,
				.frags[3] = &pkt_ipv4_udp_p2_f4,
	};
	return test_reassembly(&ipv4_4frag_case,
			RTE_SECURITY_IPSEC_TUNNEL_IPV4);
}

static int
test_reassembly_ipv6_4frag(void) {
	struct reassembly_vector ipv6_4frag_case = {
				.sa_data = &conf_aes_128_gcm,
				.full_pkt = &pkt_ipv6_udp_p2,
				.frags[0] = &pkt_ipv6_udp_p2_f1,
				.frags[1] = &pkt_ipv6_udp_p2_f2,
				.frags[2] = &pkt_ipv6_udp_p2_f3,
				.frags[3] = &pkt_ipv6_udp_p2_f4,
	};
	return test_reassembly(&ipv6_4frag_case,
			RTE_SECURITY_IPSEC_TUNNEL_IPV6);
}

static int
test_reassembly_ipv4_5frag(void) {
	struct reassembly_vector ipv4_5frag_case = {
				.sa_data = &conf_aes_128_gcm,
				.full_pkt = &pkt_ipv4_udp_p3,
				.frags[0] = &pkt_ipv4_udp_p3_f1,
				.frags[1] = &pkt_ipv4_udp_p3_f2,
				.frags[2] = &pkt_ipv4_udp_p3_f3,
				.frags[3] = &pkt_ipv4_udp_p3_f4,
				.frags[4] = &pkt_ipv4_udp_p3_f5,
	};
	return test_reassembly(&ipv4_5frag_case,
			RTE_SECURITY_IPSEC_TUNNEL_IPV4);
}

static int
test_reassembly_ipv6_5frag(void) {
	struct reassembly_vector ipv6_5frag_case = {
				.sa_data = &conf_aes_128_gcm,
				.full_pkt = &pkt_ipv6_udp_p3,
				.frags[0] = &pkt_ipv6_udp_p3_f1,
				.frags[1] = &pkt_ipv6_udp_p3_f2,
				.frags[2] = &pkt_ipv6_udp_p3_f3,
				.frags[3] = &pkt_ipv6_udp_p3_f4,
				.frags[4] = &pkt_ipv6_udp_p3_f5,
	};
	return test_reassembly(&ipv6_5frag_case,
			RTE_SECURITY_IPSEC_TUNNEL_IPV6);
}

static int
test_reassembly_incomplete(void) {
	/* Negative test case, not sending all fragments. */
	struct reassembly_vector ipv4_incomplete_case = {
				.sa_data = &conf_aes_128_gcm,
				.full_pkt = &pkt_ipv4_udp_p2,
				.frags[0] = &pkt_ipv4_udp_p2_f1,
				.frags[1] = &pkt_ipv4_udp_p2_f2,
				.frags[2] = NULL,
				.frags[3] = NULL,
	};
	return test_reassembly(&ipv4_incomplete_case,
			RTE_SECURITY_IPSEC_TUNNEL_IPV4);
}

static int
test_reassembly_overlap(void) {
	/* Negative test case, sending 1 fragment twice. */
	struct reassembly_vector ipv4_overlap_case = {
				.sa_data = &conf_aes_128_gcm,
				.full_pkt = &pkt_ipv4_udp_p2,
				.frags[0] = &pkt_ipv4_udp_p2_f1,
				.frags[1] = &pkt_ipv4_udp_p2_f2,
				.frags[2] = &pkt_ipv4_udp_p2_f2, /* overlap */
				.frags[3] = &pkt_ipv4_udp_p2_f3,
	};
	return test_reassembly(&ipv4_overlap_case,
			RTE_SECURITY_IPSEC_TUNNEL_IPV4);
}

static int
test_reassembly_out_of_order(void) {
	/* Negative test case, sending 1 fragment twice. */
	struct reassembly_vector ipv4_ooo_case = {
				.sa_data = &conf_aes_128_gcm,
				.full_pkt = &pkt_ipv4_udp_p2,
				.frags[0] = &pkt_ipv4_udp_p2_f4,
				.frags[1] = &pkt_ipv4_udp_p2_f3,
				.frags[2] = &pkt_ipv4_udp_p2_f1,
				.frags[3] = &pkt_ipv4_udp_p2_f2,
	};
	return test_reassembly(&ipv4_ooo_case,
			RTE_SECURITY_IPSEC_TUNNEL_IPV4);
}

static struct unit_test_suite inline_ipsec_testsuite  = {
	.suite_name = "Inline IPsec Ethernet Device Unit Test Suite",
	.setup = testsuite_setup,
	.teardown = testsuite_teardown,
	.unit_test_cases = {
		TEST_CASE_ST(ut_setup_inline_ipsec,
				ut_teardown_inline_ipsec,
				test_ipsec_ipv4_encap_nofrag),
		TEST_CASE_ST(ut_setup_inline_ipsec,
				ut_teardown_inline_ipsec,
				test_ipsec_ipv4_decap_nofrag),
		TEST_CASE_ST(ut_setup_inline_ipsec,
				ut_teardown_inline_ipsec,
				test_reassembly_ipv4_nofrag),
		TEST_CASE_ST(ut_setup_inline_ipsec,
				ut_teardown_inline_ipsec,
				test_reassembly_ipv4_2frag),
		TEST_CASE_ST(ut_setup_inline_ipsec,
				ut_teardown_inline_ipsec,
				test_reassembly_ipv6_2frag),
		TEST_CASE_ST(ut_setup_inline_ipsec,
				ut_teardown_inline_ipsec,
				test_reassembly_ipv4_4frag),
		TEST_CASE_ST(ut_setup_inline_ipsec,
				ut_teardown_inline_ipsec,
				test_reassembly_ipv6_4frag),
		TEST_CASE_ST(ut_setup_inline_ipsec,
				ut_teardown_inline_ipsec,
				test_reassembly_ipv4_5frag),
		TEST_CASE_ST(ut_setup_inline_ipsec,
				ut_teardown_inline_ipsec,
				test_reassembly_ipv6_5frag),
		TEST_CASE_ST(ut_setup_inline_ipsec,
				ut_teardown_inline_ipsec,
				test_reassembly_incomplete),
		TEST_CASE_ST(ut_setup_inline_ipsec,
				ut_teardown_inline_ipsec,
				test_reassembly_overlap),
		TEST_CASE_ST(ut_setup_inline_ipsec,
				ut_teardown_inline_ipsec,
				test_reassembly_out_of_order),

		TEST_CASES_END() /**< NULL terminate unit test array */
	}
};

static int
test_inline_ipsec(void)
{
	return unit_test_suite_runner(&inline_ipsec_testsuite);
}

REGISTER_TEST_COMMAND(inline_ipsec_autotest, test_inline_ipsec);

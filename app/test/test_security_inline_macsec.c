/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */


#include <stdio.h>
#include <inttypes.h>

#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_security.h>

#include "test.h"
#include "test_security_inline_macsec_vectors.h"

#ifdef RTE_EXEC_ENV_WINDOWS
static int
test_inline_macsec(void)
{
	printf("Inline MACsec not supported on Windows, skipping test\n");
	return TEST_SKIPPED;
}

#else

#define NB_ETHPORTS_USED		1
#define MEMPOOL_CACHE_SIZE		32
#define MAX_PKT_BURST			32
#define RTE_TEST_RX_DESC_DEFAULT	1024
#define RTE_TEST_TX_DESC_DEFAULT	1024
#define RTE_PORT_ALL		(~(uint16_t)0x0)

#define RX_PTHRESH 8 /**< Default values of RX prefetch threshold reg. */
#define RX_HTHRESH 8 /**< Default values of RX host threshold reg. */
#define RX_WTHRESH 0 /**< Default values of RX write-back threshold reg. */

#define TX_PTHRESH 32 /**< Default values of TX prefetch threshold reg. */
#define TX_HTHRESH 0  /**< Default values of TX host threshold reg. */
#define TX_WTHRESH 0  /**< Default values of TX write-back threshold reg. */

#define MAX_TRAFFIC_BURST		2048
#define NB_MBUF				10240

#define MCS_INVALID_SA			0xFFFF
#define MCS_MAX_FLOWS			63

static struct rte_mempool *mbufpool;
static struct rte_mempool *sess_pool;
static struct rte_mempool *sess_priv_pool;
/* ethernet addresses of ports */
static struct rte_ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

struct mcs_test_opts {
	int val_frames;
	int nb_td;
	uint16_t mtu;
	uint8_t sa_in_use;
	bool protect_frames;
	uint8_t sectag_insert_mode;
	uint8_t nb_vlan;
	uint16_t replay_win_sz;
	uint8_t replay_protect;
	uint8_t rekey_en;
};

static struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode = RTE_ETH_MQ_RX_NONE,
		.split_hdr_size = 0,
		.offloads = RTE_ETH_RX_OFFLOAD_CHECKSUM |
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

static uint16_t port_id;

static uint64_t link_mbps;

static struct rte_flow *default_flow[RTE_MAX_ETHPORTS];

static struct rte_mbuf **tx_pkts_burst;
static struct rte_mbuf **rx_pkts_burst;

static inline struct rte_mbuf *
init_packet(struct rte_mempool *mp, const uint8_t *data, unsigned int len)
{
	struct rte_mbuf *pkt;

	pkt = rte_pktmbuf_alloc(mp);
	if (pkt == NULL)
		return NULL;

	rte_memcpy(rte_pktmbuf_append(pkt, len), data, len);

	return pkt;
}

static int
init_mempools(unsigned int nb_mbuf)
{
	struct rte_security_ctx *sec_ctx;
	uint16_t nb_sess = 512;
	uint32_t sess_sz;
	char s[64];

	if (mbufpool == NULL) {
		snprintf(s, sizeof(s), "mbuf_pool");
		mbufpool = rte_pktmbuf_pool_create(s, nb_mbuf,
				MEMPOOL_CACHE_SIZE, 0,
				RTE_MBUF_DEFAULT_BUF_SIZE, SOCKET_ID_ANY);
		if (mbufpool == NULL) {
			printf("Cannot init mbuf pool\n");
			return TEST_FAILED;
		}
		printf("Allocated mbuf pool\n");
	}

	sec_ctx = rte_eth_dev_get_sec_ctx(port_id);
	if (sec_ctx == NULL) {
		printf("Device does not support Security ctx\n");
		return TEST_SKIPPED;
	}
	sess_sz = rte_security_session_get_size(sec_ctx);
	if (sess_pool == NULL) {
		snprintf(s, sizeof(s), "sess_pool");
		sess_pool = rte_mempool_create(s, nb_sess, sess_sz,
				MEMPOOL_CACHE_SIZE, 0,
				NULL, NULL, NULL, NULL,
				SOCKET_ID_ANY, 0);
		if (sess_pool == NULL) {
			printf("Cannot init sess pool\n");
			return TEST_FAILED;
		}
		printf("Allocated sess pool\n");
	}
	if (sess_priv_pool == NULL) {
		snprintf(s, sizeof(s), "sess_priv_pool");
		sess_priv_pool = rte_mempool_create(s, nb_sess, sess_sz,
				MEMPOOL_CACHE_SIZE, 0,
				NULL, NULL, NULL, NULL,
				SOCKET_ID_ANY, 0);
		if (sess_priv_pool == NULL) {
			printf("Cannot init sess_priv pool\n");
			return TEST_FAILED;
		}
		printf("Allocated sess_priv pool\n");
	}

	return 0;
}

static void
fill_macsec_sa_conf(const struct mcs_test_vector *td, struct rte_security_macsec_sa *sa,
			enum rte_security_macsec_direction dir, uint8_t an, uint8_t tci_off)
{
	sa->dir = dir;

	sa->key.data = td->sa_key.data;
	sa->key.length = td->sa_key.len;

	memcpy((uint8_t *)sa->salt, (const uint8_t *)td->salt, RTE_SECURITY_MACSEC_SALT_LEN);

	/* AN is set as per the value in secure packet in test vector */
	sa->an = an & RTE_MACSEC_AN_MASK;

	sa->xpn = td->xpn;
	/* Starting packet number which is expected to come next. It is taken
	 * from the test vector so that we can match the out packet. */
	sa->next_pn = td->secure_pkt.data[tci_off + 2];
}

static void
fill_macsec_sc_conf(const struct mcs_test_vector *td, struct rte_security_macsec_sc *sc_conf,
			enum rte_security_macsec_direction dir, uint16_t sa_id[], uint8_t tci_off)
{
	int i;

	if (dir == RTE_SECURITY_MACSEC_DIR_TX) {
		sc_conf->sc_tx.sa_id = sa_id[0];
		if (sa_id[1] != MCS_INVALID_SA) {
			sc_conf->sc_tx.sa_id_rekey = sa_id[1];
			sc_conf->sc_tx.re_key_en = 1;
		}
		sc_conf->sc_tx.active = 1;
		/* is SCI valid */
		if (td->secure_pkt.data[tci_off] & RTE_MACSEC_TCI_SC) {
			memcpy(&sc_conf->sc_tx.sci, &td->secure_pkt.data[tci_off + 6],
					sizeof(sc_conf->sc_tx.sci));
			sc_conf->sc_tx.sci = rte_be_to_cpu_64(sc_conf->sc_tx.sci);
		} else if (td->secure_pkt.data[tci_off] & RTE_MACSEC_TCI_ES) {
			/* sci = source_mac + port_id when ES.bit = 1 & SC.bit = 0 */
			const uint8_t *smac = td->plain_pkt.data + RTE_ETHER_ADDR_LEN;
			uint8_t *ptr = (uint8_t *)&sc_conf->sc_tx.sci;

			ptr[0] = 0x01; /*TODO: port_id */
			ptr[1] = 0;
			for (uint8_t j = 0; j < RTE_ETHER_ADDR_LEN; j++)
				ptr[2 + j] = smac[RTE_ETHER_ADDR_LEN - 1 - j];
		} else {
			/* use some default SCI */
			sc_conf->sc_tx.sci = 0xf1341e023a2b1c5d;
		}
	} else {
		for (i = 0; i < RTE_SECURITY_MACSEC_NUM_AN; i++) {
			sc_conf->sc_rx.sa_id[i] = sa_id[i];
			sc_conf->sc_rx.sa_in_use[i] = 1;
		}
		sc_conf->sc_rx.active = 1;
	}
}


/* Create Inline MACsec session */
static int
fill_session_conf(const struct mcs_test_vector *td, uint16_t portid __rte_unused,
		const struct mcs_test_opts *opts,
		struct rte_security_session_conf *sess_conf,
		enum rte_security_macsec_direction dir,
		uint16_t sc_id,
		uint8_t tci_off)
{
//	struct rte_security_capability_idx sec_cap_idx;
//	const struct rte_security_capability *sec_cap;

	sess_conf->action_type = RTE_SECURITY_ACTION_TYPE_INLINE_PROTOCOL;
	sess_conf->protocol = RTE_SECURITY_PROTOCOL_MACSEC;
	sess_conf->macsec.dir = dir;
	sess_conf->macsec.alg = td->alg;
	sess_conf->macsec.cipher_off = 0;
	sess_conf->macsec.sci = (uint64_t)td->secure_pkt.data[tci_off + 6];
	sess_conf->macsec.sc_id = sc_id;
	if (dir == RTE_SECURITY_MACSEC_DIR_TX) {
		sess_conf->macsec.tx_secy.mtu = opts->mtu;
		sess_conf->macsec.tx_secy.sectag_off = (opts->sectag_insert_mode == 1) ?
							2 * RTE_ETHER_ADDR_LEN :
							RTE_VLAN_HLEN;
		sess_conf->macsec.tx_secy.sectag_insert_mode = opts->sectag_insert_mode;
		sess_conf->macsec.tx_secy.icv_include_da_sa = 1;
		sess_conf->macsec.tx_secy.ctrl_port_enable = 1;
		sess_conf->macsec.tx_secy.sectag_version = 0;
		sess_conf->macsec.tx_secy.end_station =
					td->secure_pkt.data[tci_off] & RTE_MACSEC_TCI_ES;
		sess_conf->macsec.tx_secy.send_sci =
					td->secure_pkt.data[tci_off] & RTE_MACSEC_TCI_SC;
		sess_conf->macsec.tx_secy.scb =
					td->secure_pkt.data[tci_off] & RTE_MACSEC_TCI_SCB;
		sess_conf->macsec.tx_secy.encrypt = 1;
	} else {
		sess_conf->macsec.rx_secy.replay_win_sz = opts->replay_win_sz;
		sess_conf->macsec.rx_secy.replay_protect = opts->replay_protect;
		sess_conf->macsec.rx_secy.validate_frames = opts->val_frames;
		sess_conf->macsec.rx_secy.icv_include_da_sa = 1;
		sess_conf->macsec.rx_secy.ctrl_port_enable = 1;
		sess_conf->macsec.rx_secy.preserve_sectag = 0;
		sess_conf->macsec.rx_secy.preserve_icv = 0;
	}
//	sec_cap = rte_security_capability_get(sec_ctx, &sec_cap_idx);
//	if (sec_cap == NULL) {
//		printf("No capabilities registered\n");
//		return TEST_SKIPPED;
//	}

	return 0;
}
static int
create_default_flow(const struct mcs_test_vector *td, uint16_t portid,
		    enum rte_security_macsec_direction dir, void *sess)
{
	struct rte_flow_action action[2];
	struct rte_flow_item pattern[2];
	struct rte_flow_attr attr = {0};
	struct rte_flow_error err;
	struct rte_flow *flow;
	struct rte_flow_item_eth eth = {0};
	int ret;

	eth.has_vlan = 0;
	if (dir == RTE_SECURITY_MACSEC_DIR_TX)
		memcpy(&eth.hdr, td->plain_pkt.data, RTE_ETHER_HDR_LEN);
	else
		memcpy(&eth.hdr, td->secure_pkt.data, RTE_ETHER_HDR_LEN);

	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[0].spec = &eth;
	pattern[0].mask = &rte_flow_item_eth_mask;
	pattern[0].last = &eth;
	pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

	action[0].type = RTE_FLOW_ACTION_TYPE_SECURITY;
	action[0].conf = sess;
	action[1].type = RTE_FLOW_ACTION_TYPE_END;
	action[1].conf = NULL;

	attr.ingress = dir;

	ret = rte_flow_validate(portid, &attr, pattern, action, &err);
	if (ret) {
		printf("\nValidate flow failed, ret = %d\n", ret);
		return -1;
	}
	flow = rte_flow_create(portid, &attr, pattern, action, &err);
	if (flow == NULL) {
		printf("\nDefault flow rule create failed\n");
		return -1;
	}

	default_flow[portid] = flow;

	return 0;
}

static void
destroy_default_flow(uint16_t portid)
{
	struct rte_flow_error err;
	int ret;

	if (!default_flow[portid])
		return;
	ret = rte_flow_destroy(portid, default_flow[portid], &err);
	if (ret) {
		printf("\nDefault flow rule destroy failed\n");
		return;
	}
	default_flow[portid] = NULL;
}

static void
print_ethaddr(const char *name, const struct rte_ether_addr *eth_addr)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];
	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s%s", name, buf);
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

static int
test_macsec_post_process(struct rte_mbuf *m, const struct mcs_test_vector *td,
			enum mcs_op op)
{
	const uint8_t *dptr;
	uint16_t pkt_len;

	if (op == MCS_DECAP || op == MCS_ENCAP_DECAP ||
			op == MCS_VERIFY_ONLY || op == MCS_AUTH_VERIFY) {
		dptr = td->plain_pkt.data;
		pkt_len = td->plain_pkt.len;
	} else {
		dptr = td->secure_pkt.data;
		pkt_len = td->secure_pkt.len;
	}

	if (memcmp(rte_pktmbuf_mtod(m, uint8_t *), dptr, pkt_len)) {
		printf("\nData comparison failed for td.");
		rte_pktmbuf_dump(stdout, m, m->pkt_len);
		rte_hexdump(stdout, "expected_data", dptr, pkt_len);
		return TEST_FAILED;
	}

	return TEST_SUCCESS;
}

static int
test_macsec(const struct mcs_test_vector *td[], enum mcs_op op, const struct mcs_test_opts *opts)
{
	uint16_t rx_sa_id[MCS_MAX_FLOWS][RTE_SECURITY_MACSEC_NUM_AN] = {0};
	uint16_t tx_sa_id[MCS_MAX_FLOWS][2] = {0};
	uint16_t rx_sc_id[MCS_MAX_FLOWS] = {0};
	uint16_t tx_sc_id[MCS_MAX_FLOWS] = {0};
	struct rte_security_session *rx_sess[MCS_MAX_FLOWS];
	struct rte_security_session *tx_sess[MCS_MAX_FLOWS];
	struct rte_security_session_conf sess_conf = {0};
	struct rte_security_macsec_sa sa_conf = {0};
	struct rte_security_macsec_sc sc_conf = {0};
	struct rte_security_ctx *ctx;
	int nb_rx = 0, nb_sent;
	int i, j = 0, ret;
	uint8_t tci_off;

	memset(rx_pkts_burst, 0, sizeof(rx_pkts_burst[0]) * opts->nb_td);

	ctx = (struct rte_security_ctx *)rte_eth_dev_get_sec_ctx(port_id);
	if (ctx == NULL) {
		printf("Ethernet device doesn't support security features.\n");
		return TEST_SKIPPED;
	}

	tci_off = (opts->sectag_insert_mode == 1) ? RTE_ETHER_HDR_LEN :
			RTE_ETHER_HDR_LEN + (opts->nb_vlan * RTE_VLAN_HLEN);

	for (i = 0; i < opts->nb_td; i++) {
		tx_pkts_burst[i] = init_packet(mbufpool, td[i]->plain_pkt.data,
						td[i]->plain_pkt.len);
		if (tx_pkts_burst[i] == NULL) {
			while (i--)
				rte_pktmbuf_free(tx_pkts_burst[i]);
			ret = TEST_FAILED;
			goto out;
		}

		if (op == MCS_DECAP || op == MCS_ENCAP_DECAP ||
				op == MCS_VERIFY_ONLY || op == MCS_AUTH_VERIFY) {
			for (j = 0; j < RTE_SECURITY_MACSEC_NUM_AN; j++) {
				/* For simplicity, using same SA conf for all AN */
				fill_macsec_sa_conf(td[i], &sa_conf,
						RTE_SECURITY_MACSEC_DIR_RX, j, tci_off);
				rx_sa_id[i][j] = rte_security_macsec_sa_create(ctx, &sa_conf);
			}
			fill_macsec_sc_conf(td[i], &sc_conf,
					RTE_SECURITY_MACSEC_DIR_RX, rx_sa_id[i], tci_off);
			rx_sc_id[i] = rte_security_macsec_sc_create(ctx, &sc_conf);

			/* Create Inline IPsec session. */
			ret = fill_session_conf(td[i], port_id, opts, &sess_conf,
					RTE_SECURITY_MACSEC_DIR_RX, rx_sc_id[i], tci_off);
			if (ret)
				return TEST_FAILED;

			rx_sess[i] = rte_security_session_create(ctx, &sess_conf,
					sess_pool, sess_priv_pool);
			if (rx_sess[i] == NULL) {
				printf("SEC Session init failed.\n");
				return TEST_FAILED;
			}
			ret = create_default_flow(td[i], port_id,
					RTE_SECURITY_MACSEC_DIR_RX, rx_sess[i]);
			if (ret)
				goto out;
		}
		if (op == MCS_ENCAP || op == MCS_ENCAP_DECAP ||
				op == MCS_AUTH_ONLY || op == MCS_AUTH_VERIFY) {
			fill_macsec_sa_conf(td[i], &sa_conf,
					RTE_SECURITY_MACSEC_DIR_TX,
					td[i]->secure_pkt.data[tci_off] & RTE_MACSEC_AN_MASK,
					tci_off);
			tx_sa_id[i][0] = rte_security_macsec_sa_create(ctx, &sa_conf);
			tx_sa_id[i][1] = MCS_INVALID_SA;
			if (opts->rekey_en) {
				/* Creating SA with same sa_conf for now. */
				tx_sa_id[i][1] = rte_security_macsec_sa_create(ctx, &sa_conf);
			}
			fill_macsec_sc_conf(td[i], &sc_conf,
					RTE_SECURITY_MACSEC_DIR_TX, tx_sa_id[i], tci_off);
			tx_sc_id[i] = rte_security_macsec_sc_create(ctx, &sc_conf);

			/* Create Inline IPsec session. */
			ret = fill_session_conf(td[i], port_id, opts, &sess_conf,
					RTE_SECURITY_MACSEC_DIR_TX, tx_sc_id[i], tci_off);
			if (ret)
				return TEST_FAILED;

			tx_sess[i] = rte_security_session_create(ctx, &sess_conf,
					sess_pool, sess_priv_pool);
			if (tx_sess[i] == NULL) {
				printf("SEC Session init failed.\n");
				return TEST_FAILED;
			}
			ret = create_default_flow(td[i], port_id,
					RTE_SECURITY_MACSEC_DIR_TX, tx_sess[i]);
			if (ret)
				goto out;

			tx_pkts_burst[i]->ol_flags |= RTE_MBUF_F_TX_SEC_OFFLOAD;
		}
	}

	/* Send packet to ethdev for inline MACsec processing. */
	nb_sent = rte_eth_tx_burst(port_id, 0, tx_pkts_burst, opts->nb_td);

	if (nb_sent != opts->nb_td) {
		printf("\nUnable to TX %d packets, sent: %i", opts->nb_td, nb_sent);
		for ( ; nb_sent < opts->nb_td; nb_sent++)
			rte_pktmbuf_free(tx_pkts_burst[nb_sent]);
		ret = TEST_FAILED;
		goto out;
	}

	rte_pause();

	/* Receive back packet on loopback interface. */
	do {
		rte_delay_ms(1);
		nb_rx += rte_eth_rx_burst(port_id, 0,
				&rx_pkts_burst[nb_rx],
				nb_sent - nb_rx);
		if (nb_rx >= nb_sent)
			break;
	} while (j++ < 5 || nb_rx == 0);

	if (nb_rx != nb_sent) {
		printf("\nUnable to RX all %d packets, received(%i)",
				nb_sent, nb_rx);
		while (--nb_rx >= 0)
			rte_pktmbuf_free(rx_pkts_burst[nb_rx]);
		ret = TEST_FAILED;
		goto out;
	}

	for (i = 0; i < nb_rx; i++) {
		rte_pktmbuf_adj(rx_pkts_burst[i], RTE_ETHER_HDR_LEN);

		ret = test_macsec_post_process(rx_pkts_burst[i], td[i], op);
		if (ret != TEST_SUCCESS) {
			for ( ; i < nb_rx; i++)
				rte_pktmbuf_free(rx_pkts_burst[i]);
			goto out;
		}

		rte_pktmbuf_free(rx_pkts_burst[i]);
		rx_pkts_burst[i] = NULL;
	}

out:
	destroy_default_flow(port_id);

	/* Destroy session so that other cases can create the session again */
	for (i = 0; i < opts->nb_td; i++) {
		if (op == MCS_ENCAP || op == MCS_ENCAP_DECAP ||
				op == MCS_AUTH_ONLY || op == MCS_AUTH_VERIFY) {
			rte_security_session_destroy(ctx, tx_sess[i]);
			tx_sess[i] = NULL;
			rte_security_macsec_sc_destroy(ctx, tx_sc_id[i]);
			for (j = 0; j < 2; j++)
				rte_security_macsec_sa_destroy(ctx, tx_sa_id[i][j]);
		}
		if (op == MCS_DECAP || op == MCS_ENCAP_DECAP ||
				op == MCS_VERIFY_ONLY || op == MCS_AUTH_VERIFY) {
			rte_security_session_destroy(ctx, rx_sess[i]);
			rx_sess[i] = NULL;
			rte_security_macsec_sc_destroy(ctx, rx_sc_id[i]);
			for (j = 0; j < RTE_SECURITY_MACSEC_NUM_AN; j++)
				rte_security_macsec_sa_destroy(ctx, rx_sa_id[i][j]);
		}

	}

	return ret;
}

static int
test_inline_macsec_encap_all(const void *data __rte_unused)
{
	const struct mcs_test_vector *cur_td;
	struct mcs_test_opts opts = {0};
	int err, all_err = 0;
	int i, size;

	opts.val_frames = RTE_SECURITY_MACSEC_VALIDATE_STRICT;
	opts.protect_frames = true;
	opts.sa_in_use = 1;
	opts.nb_td = 1;
	opts.sectag_insert_mode = 1;
	opts.mtu = RTE_ETHER_MTU;

	size = (sizeof(list_mcs_cipher_vectors) / sizeof((list_mcs_cipher_vectors)[0]));

	for (i = 0; i < size; i++) {
		cur_td = &list_mcs_cipher_vectors[i];
		err = test_macsec(&cur_td, MCS_ENCAP, &opts);
		if (err) {
			printf("\nCipher Auth Encryption case %d failed", cur_td->test_idx);
			err = -1;
		} else {
			printf("\nCipher Auth Encryption case %d Passed", cur_td->test_idx);
			err = 0;
		}
		all_err += err;
	}
	printf("\n%s: Success: %d, Failure: %d\n", __func__, size + all_err, -all_err);

	return all_err;
}

static int
ut_setup_inline_macsec(void)
{
	int ret;

	/* Start device */
	ret = rte_eth_dev_start(port_id);
	if (ret < 0) {
		printf("rte_eth_dev_start: err=%d, port=%d\n",
			ret, port_id);
		return ret;
	}
	/* always enable promiscuous */
	ret = rte_eth_promiscuous_enable(port_id);
	if (ret != 0) {
		printf("rte_eth_promiscuous_enable: err=%s, port=%d\n",
			rte_strerror(-ret), port_id);
		return ret;
	}

	check_all_ports_link_status(1, RTE_PORT_ALL);

	return 0;
}

static void
ut_teardown_inline_macsec(void)
{
	uint16_t portid;
	int ret;

	/* port tear down */
	RTE_ETH_FOREACH_DEV(portid) {
		ret = rte_eth_dev_stop(portid);
		if (ret != 0)
			printf("rte_eth_dev_stop: err=%s, port=%u\n",
			       rte_strerror(-ret), portid);

	}
}

static int
inline_macsec_testsuite_setup(void)
{
	uint16_t nb_rxd;
	uint16_t nb_txd;
	uint16_t nb_ports;
	int ret;
	uint16_t nb_rx_queue = 1, nb_tx_queue = 1;

	printf("Start inline IPsec test.\n");

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports < NB_ETHPORTS_USED) {
		printf("At least %u port(s) used for test\n",
		       NB_ETHPORTS_USED);
		return TEST_SKIPPED;
	}

	ret = init_mempools(NB_MBUF);
	if (ret)
		return ret;

	if (tx_pkts_burst == NULL) {
		tx_pkts_burst = (struct rte_mbuf **)rte_calloc("tx_buff",
					  MAX_TRAFFIC_BURST,
					  sizeof(void *),
					  RTE_CACHE_LINE_SIZE);
		if (!tx_pkts_burst)
			return TEST_FAILED;

		rx_pkts_burst = (struct rte_mbuf **)rte_calloc("rx_buff",
					  MAX_TRAFFIC_BURST,
					  sizeof(void *),
					  RTE_CACHE_LINE_SIZE);
		if (!rx_pkts_burst)
			return TEST_FAILED;
	}

	printf("Generate %d packets\n", MAX_TRAFFIC_BURST);

	nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
	nb_txd = RTE_TEST_TX_DESC_DEFAULT;

	/* configuring port 0 for the test is enough */
	port_id = 0;
	/* port configure */
	ret = rte_eth_dev_configure(port_id, nb_rx_queue,
				    nb_tx_queue, &port_conf);
	if (ret < 0) {
		printf("Cannot configure device: err=%d, port=%d\n",
			 ret, port_id);
		return ret;
	}
	ret = rte_eth_macaddr_get(port_id, &ports_eth_addr[port_id]);
	if (ret < 0) {
		printf("Cannot get mac address: err=%d, port=%d\n",
			 ret, port_id);
		return ret;
	}
	printf("Port %u ", port_id);
	print_ethaddr("Address:", &ports_eth_addr[port_id]);
	printf("\n");

	/* tx queue setup */
	ret = rte_eth_tx_queue_setup(port_id, 0, nb_txd,
				     SOCKET_ID_ANY, &tx_conf);
	if (ret < 0) {
		printf("rte_eth_tx_queue_setup: err=%d, port=%d\n",
				ret, port_id);
		return ret;
	}
	/* rx queue steup */
	ret = rte_eth_rx_queue_setup(port_id, 0, nb_rxd, SOCKET_ID_ANY,
				     &rx_conf, mbufpool);
	if (ret < 0) {
		printf("rte_eth_rx_queue_setup: err=%d, port=%d\n",
				ret, port_id);
		return ret;
	}

	return 0;
}

static void
inline_macsec_testsuite_teardown(void)
{
	uint16_t portid;
	int ret;

	/* port tear down */
	RTE_ETH_FOREACH_DEV(portid) {
		ret = rte_eth_dev_reset(portid);
		if (ret != 0)
			printf("rte_eth_dev_reset: err=%s, port=%u\n",
			       rte_strerror(-ret), port_id);
	}
	rte_free(tx_pkts_burst);
	rte_free(rx_pkts_burst);
}


static struct unit_test_suite inline_macsec_testsuite  = {
	.suite_name = "Inline MACsec Ethernet Device Unit Test Suite",
	.unit_test_cases = {
		TEST_CASE_NAMED_ST(
			"MACsec encap(Cipher+Auth) known vector",
			ut_setup_inline_macsec, ut_teardown_inline_macsec,
			test_inline_macsec_encap_all),

		TEST_CASES_END() /**< NULL terminate unit test array */
	},
};
static int
test_inline_macsec(void)
{
	inline_macsec_testsuite.setup = inline_macsec_testsuite_setup;
	inline_macsec_testsuite.teardown = inline_macsec_testsuite_teardown;
	return unit_test_suite_runner(&inline_macsec_testsuite);
}

#endif /* !RTE_EXEC_ENV_WINDOWS */

REGISTER_TEST_COMMAND(inline_macsec_autotest, test_inline_macsec);

#ifndef __RNP_RXTX_H__
#define __RNP_RXTX_H__

uint32_t rnp_dev_rx_queue_count(void *rx_queue);
int rnp_dev_rx_descriptor_status(void *rx_queue, uint16_t offset);
int rnp_dev_tx_descriptor_status(void *tx_queue, uint16_t offset);
uint16_t
rnp_recv_pkts(void *_rxq, struct rte_mbuf **rx_pkts, uint16_t nb_pkts);
uint16_t
rnp_xmit_pkts(void *_txq, struct rte_mbuf **tx_pkts, uint16_t nb_pkts);
uint16_t rnp_prep_pkts(void *tx_queue,
		struct rte_mbuf **tx_pkts,
		uint16_t nb_pkts);
#endif /* __RNP_RXTX_H__ */

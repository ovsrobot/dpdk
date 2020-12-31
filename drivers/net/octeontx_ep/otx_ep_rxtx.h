/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2019 Marvell International Ltd.
 */

#ifndef _OTX_EP_RXTX_H_
#define _OTX_EP_RXTX_H_

#define OTX_EP_RXD_ALIGN 1
#define OTX_EP_TXD_ALIGN 1
#define OTX_EP_MAX_DELAYED_PKT_RETRIES 10000
static inline uint32_t
otx_ep_incr_index(uint32_t index, uint32_t count, uint32_t max)
{
	if ((index + count) >= max)
		index = index + count - max;
	else
		index += count;

	return index;
}
uint16_t
otx_ep_recv_pkts(void *rx_queue,
		  struct rte_mbuf **rx_pkts,
		  uint16_t budget);
#endif /* _OTX_EP_RXTX_H_ */

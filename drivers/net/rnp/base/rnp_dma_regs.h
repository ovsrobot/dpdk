#ifndef __RNP_REGS_H__
#define __RNP_REGS_H__

#include "rnp_osdep.h"

/* mac address offset */
#define RNP_DMA_CTRL				(0x4)
#define RNP_VEB_BYPASS_EN			BIT(4)
#define RNP_DMA_MEM_CFG_LE			(0 << 5)
#define TSNR10_DMA_MEM_CFG_BE			(1 << 5)
#define RNP_DMA_SCATTER_MEM_SHIFT		(16)

#define RNP_FIRMWARE_SYNC			(0xc)
#define RNP_FIRMWARE_SYNC_MASK			GENMASK(31, 16)
#define RNP_FIRMWARE_SYNC_MAGIC			(0xa5a40000)
#define RNP_DRIVER_REMOVE			(0x5a000000)
/* 1BIT <-> 16 bytes Dma Addr Size*/
#define RNP_DMA_SCATTER_MEM_MASK		GENMASK(31, 16)
#define RNP_DMA_TX_MAP_MODE_SHIFT		(12)
#define RNP_DMA_TX_MAP_MODE_MASK		GENMASK(15, 12)
#define RNP_DMA_RX_MEM_PAD_EN			BIT(8)
/* === queue register ===== */
/* enable */
#define RNP_DMA_RXQ_START(qid)			_RING_(0x0010 + 0x100 * (qid))
#define RNP_DMA_RXQ_READY(qid)			_RING_(0x0014 + 0x100 * (qid))
#define RNP_DMA_TXQ_START(qid)			_RING_(0x0018 + 0x100 * (qid))
#define RNP_DMA_TXQ_READY(qid)			_RING_(0x001c + 0x100 * (qid))

#define RNP_DMA_INT_STAT(qid)			_RING_(0x0020 + 0x100 * (qid))
#define RNP_DMA_INT_MASK(qid)			_RING_(0x0024 + 0x100 * (qid))
#define RNP_TX_INT_MASK				BIT(1)
#define RNP_RX_INT_MASK				BIT(0)
#define RNP_DMA_INT_CLER(qid)			_RING_(0x0028 + 0x100 * (qid))

/* rx-queue */
#define RNP_DMA_RXQ_BASE_ADDR_HI(qid)		_RING_(0x0030 + 0x100 * (qid))
#define RNP_DMA_RXQ_BASE_ADDR_LO(qid)		_RING_(0x0034 + 0x100 * (qid))
#define RNP_DMA_RXQ_LEN(qid)			_RING_(0x0038 + 0x100 * (qid))
#define RNP_DMA_RXQ_HEAD(qid)			_RING_(0x003c + 0x100 * (qid))
#define RNP_DMA_RXQ_TAIL(qid)			_RING_(0x0040 + 0x100 * (qid))
#define RNP_DMA_RXQ_DESC_FETCH_CTRL(qid)	_RING_(0x0044 + 0x100 * (qid))
#define RNP_DMA_RXQ_INT_DELAY_TIMER(qid)	_RING_(0x0048 + 0x100 * (qid))
#define RNP_DMA_RXQ_INT_DELAY_PKTCNT(qidx)	_RING_(0x004c + 0x100 * (qid))
#define RNP_DMA_RXQ_RX_PRI_LVL(qid)		_RING_(0x0050 + 0x100 * (qid))
#define RNP_DMA_RXQ_DROP_TIMEOUT_TH(qid)	_RING_(0x0054 + 0x100 * (qid))
/* tx-queue */
#define RNP_DMA_TXQ_BASE_ADDR_HI(qid)		_RING_(0x0060 + 0x100 * (qid))
#define RNP_DMA_TXQ_BASE_ADDR_LO(qid)		_RING_(0x0064 + 0x100 * (qid))
#define RNP_DMA_TXQ_LEN(qid)			_RING_(0x0068 + 0x100 * (qid))
#define RNP_DMA_TXQ_HEAD(qid)			_RING_(0x006c + 0x100 * (qid))
#define RNP_DMA_TXQ_TAIL(qid)			_RING_(0x0070 + 0x100 * (qid))
#define RNP_DMA_TXQ_DESC_FETCH_CTRL(qid)	_RING_(0x0074 + 0x100 * (qid))
#define RNP_DMA_TXQ_INT_DELAY_TIMER(qid)	_RING_(0x0078 + 0x100 * (qid))
#define RNP_DMA_TXQ_INT_DELAY_PKTCNT(qid)	_RING_(0x007c + 0x100 * (qid))

#define RNP_DMA_TXQ_PRI_LVL(qid)		_RING_(0x0080 + 0x100 * (qid))
#define RNP_DMA_TXQ_RATE_CTRL_TH(qid)		_RING_(0x0084 + 0x100 * (qid))
#define RNP_DMA_TXQ_RATE_CTRL_TM(qid)		_RING_(0x0088 + 0x100 * (qid))

/* VEB Table Register */
#define RNP_VBE_MAC_LO(port, nr)		_RING_(0x00a0 + (4 * (port)) + \
						(0x100 * (nr)))
#define RNP_VBE_MAC_HI(port, nr)		_RING_(0x00b0 + (4 * (port)) + \
						(0x100 * (nr)))
#define RNP_VEB_VID_CFG(port, nr)		_RING_(0x00c0 + (4 * (port)) + \
						(0x100 * (nr)))
#define RNP_VEB_VF_RING(port, nr)		_RING_(0x00d0 + (4 * (port)) + \
						(0x100 * (nr)))
#define RNP_MAX_VEB_TB				(64)
#define RNP_VEB_RING_CFG_OFFSET			(8)
#define RNP_VEB_SWITCH_VF_EN			BIT(7)
#define MAX_VEB_TABLES_NUM			(4)
#endif /* RNP_DMA_REGS_H_ */

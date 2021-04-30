/* SPDX-License-Identifier: BSD-3.0-Clause
 * Copyright(c) 2021 Advanced Micro Devices, Inc. All rights reserved.
 */

#ifndef __PT_DEV_H__
#define __PT_DEV_H__

#include <rte_bus_pci.h>
#include <rte_byteorder.h>
#include <rte_io.h>
#include <rte_pci.h>
#include <rte_spinlock.h>
#include <rte_rawdev.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BIT(nr)				(1 << (nr))

#define BITS_PER_LONG   (__SIZEOF_LONG__ * 8)
#define GENMASK(h, l)   (((~0UL) << (l)) & (~0UL >> (BITS_PER_LONG - 1 - (h))))

#define MAX_HW_QUEUES			1

/* Register Mappings */

#define CMD_QUEUE_PRIO_OFFSET		0x00
#define CMD_REQID_CONFIG_OFFSET		0x04
#define CMD_TIMEOUT_OFFSET		0x08
#define CMD_TIMEOUT_GRANULARITY		0x0C
#define CMD_PTDMA_VERSION		0x10

#define CMD_Q_CONTROL_BASE		0x0000
#define CMD_Q_TAIL_LO_BASE		0x0004
#define CMD_Q_HEAD_LO_BASE		0x0008
#define CMD_Q_INT_ENABLE_BASE		0x000C
#define CMD_Q_INTERRUPT_STATUS_BASE	0x0010

#define CMD_Q_STATUS_BASE		0x0100
#define CMD_Q_INT_STATUS_BASE		0x0104
#define CMD_Q_DMA_STATUS_BASE		0x0108
#define CMD_Q_DMA_READ_STATUS_BASE	0x010C
#define CMD_Q_DMA_WRITE_STATUS_BASE	0x0110
#define CMD_Q_ABORT_BASE		0x0114
#define CMD_Q_AX_CACHE_BASE		0x0118

#define CMD_CONFIG_OFFSET		0x1120
#define CMD_CLK_GATE_CTL_OFFSET		0x6004

#define CMD_DESC_DW0_VAL		0x500012

/* Address offset for virtual queue registers */
#define CMD_Q_STATUS_INCR		0x1000

/* Bit masks */
#define CMD_CONFIG_REQID		0
#define CMD_TIMEOUT_DISABLE		0
#define CMD_CLK_DYN_GATING_DIS		0
#define CMD_CLK_SW_GATE_MODE		0
#define CMD_CLK_GATE_CTL		0
#define CMD_QUEUE_PRIO			GENMASK(2, 1)
#define CMD_CONFIG_VHB_EN		BIT(0)
#define CMD_CLK_DYN_GATING_EN		BIT(0)
#define CMD_CLK_HW_GATE_MODE		BIT(0)
#define CMD_CLK_GATE_ON_DELAY		BIT(12)
#define CMD_CLK_GATE_OFF_DELAY		BIT(12)

#define CMD_CLK_GATE_CONFIG		(CMD_CLK_GATE_CTL | \
					CMD_CLK_HW_GATE_MODE | \
					CMD_CLK_GATE_ON_DELAY | \
					CMD_CLK_DYN_GATING_EN | \
					CMD_CLK_GATE_OFF_DELAY)

#define CMD_Q_LEN			32
#define CMD_Q_RUN			BIT(0)
#define CMD_Q_HALT			BIT(1)
#define CMD_Q_MEM_LOCATION		BIT(2)
#define CMD_Q_SIZE			GENMASK(4, 0)
#define CMD_Q_SHIFT			GENMASK(1, 0)
#define COMMANDS_PER_QUEUE		8192


#define QUEUE_SIZE_VAL			((ffs(COMMANDS_PER_QUEUE) - 2) & \
						CMD_Q_SIZE)
#define Q_PTR_MASK			(2 << (QUEUE_SIZE_VAL + 5) - 1)
#define Q_DESC_SIZE			sizeof(struct ptdma_desc)
#define Q_SIZE(n)			(COMMANDS_PER_QUEUE * (n))

#define INT_COMPLETION			BIT(0)
#define INT_ERROR			BIT(1)
#define INT_QUEUE_STOPPED		BIT(2)
#define INT_EMPTY_QUEUE			BIT(3)
#define SUPPORTED_INTERRUPTS		(INT_COMPLETION | INT_ERROR)
#define ALL_INTERRUPTS			(INT_COMPLETION | INT_ERROR | \
					INT_QUEUE_STOPPED)

/****** Local Storage Block ******/
#define LSB_START			0
#define LSB_END				127
#define LSB_COUNT			(LSB_END - LSB_START + 1)

#define LSB_REGION_WIDTH		5
#define MAX_LSB_CNT			8

#define LSB_SIZE			16
#define LSB_ITEM_SIZE			128
#define SLSB_MAP_SIZE			(MAX_LSB_CNT * LSB_SIZE)
#define LSB_ENTRY_NUMBER(LSB_ADDR)	(LSB_ADDR / LSB_ITEM_SIZE)


#define PT_DMAPOOL_MAX_SIZE		64
#define PT_DMAPOOL_ALIGN		BIT(5)

#define PT_PASSTHRU_BLOCKSIZE		512

/* General PTDMA Defines */

#define PTDMA_SB_BYTES			32
#define	PTDMA_ENGINE_PASSTHRU		0x5

/* Word 0 */
#define PTDMA_CMD_DW0(p)		((p)->dw0)
#define PTDMA_CMD_SOC(p)		(PTDMA_CMD_DW0(p).soc)
#define PTDMA_CMD_IOC(p)		(PTDMA_CMD_DW0(p).ioc)
#define PTDMA_CMD_INIT(p)		(PTDMA_CMD_DW0(p).init)
#define PTDMA_CMD_EOM(p)		(PTDMA_CMD_DW0(p).eom)
#define PTDMA_CMD_FUNCTION(p)		(PTDMA_CMD_DW0(p).function)
#define PTDMA_CMD_ENGINE(p)		(PTDMA_CMD_DW0(p).engine)
#define PTDMA_CMD_PROT(p)		(PTDMA_CMD_DW0(p).prot)

/* Word 1 */
#define PTDMA_CMD_DW1(p)		((p)->length)
#define PTDMA_CMD_LEN(p)		(PTDMA_CMD_DW1(p))

/* Word 2 */
#define PTDMA_CMD_DW2(p)		((p)->src_lo)
#define PTDMA_CMD_SRC_LO(p)		(PTDMA_CMD_DW2(p))

/* Word 3 */
#define PTDMA_CMD_DW3(p)		((p)->dw3)
#define PTDMA_CMD_SRC_MEM(p)		((p)->dw3.src_mem)
#define PTDMA_CMD_SRC_HI(p)		((p)->dw3.src_hi)
#define PTDMA_CMD_LSB_ID(p)		((p)->dw3.lsb_cxt_id)
#define PTDMA_CMD_FIX_SRC(p)		((p)->dw3.fixed)

/* Words 4/5 */
#define PTDMA_CMD_DST_LO(p)		((p)->dst_lo)
#define PTDMA_CMD_DW5(p)		((p)->dw5.dst_hi)
#define PTDMA_CMD_DST_HI(p)		(PTDMA_CMD_DW5(p))
#define PTDMA_CMD_DST_MEM(p)		((p)->dw5.dst_mem)
#define PTDMA_CMD_FIX_DST(p)		((p)->dw5.fixed)

/* bitmap */
enum {
	BITS_PER_WORD = sizeof(unsigned long) * CHAR_BIT
};

#define WORD_OFFSET(b) ((b) / BITS_PER_WORD)
#define BIT_OFFSET(b)  ((b) % BITS_PER_WORD)

#define PTDMA_DIV_ROUND_UP(n, d)  (((n) + (d) - 1) / (d))
#define PTDMA_BITMAP_SIZE(nr) \
	PTDMA_DIV_ROUND_UP(nr, CHAR_BIT * sizeof(unsigned long))

#define PTDMA_BITMAP_FIRST_WORD_MASK(start) \
	(~0UL << ((start) & (BITS_PER_WORD - 1)))
#define PTDMA_BITMAP_LAST_WORD_MASK(nbits) \
	(~0UL >> (-(nbits) & (BITS_PER_WORD - 1)))

#define __ptdma_round_mask(x, y) ((typeof(x))((y)-1))
#define ptdma_round_down(x, y) ((x) & ~__ptdma_round_mask(x, y))

/** PTDMA registers Write/Read */
static inline void ptdma_pci_reg_write(void *base, int offset,
					uint32_t value)
{
	volatile void *reg_addr = ((uint8_t *)base + offset);
	rte_write32((rte_cpu_to_le_32(value)), reg_addr);
}

static inline uint32_t ptdma_pci_reg_read(void *base, int offset)
{
	volatile void *reg_addr = ((uint8_t *)base + offset);
	return rte_le_to_cpu_32(rte_read32(reg_addr));
}

#define PTDMA_READ_REG(hw_addr, reg_offset) \
	ptdma_pci_reg_read(hw_addr, reg_offset)

#define PTDMA_WRITE_REG(hw_addr, reg_offset, value) \
	ptdma_pci_reg_write(hw_addr, reg_offset, value)

/**
 * A structure describing a PTDMA command queue.
 */
struct ptdma_cmd_queue {
	struct ptdma_device *dev;
	char memz_name[RTE_MEMZONE_NAMESIZE];

	/* Queue identifier */
	uint64_t id;	/**< queue id */
	uint64_t qidx;	/**< queue index */
	uint64_t qsize;	/**< queue size */

	/* Queue address */
	struct ptdma_desc *qbase_desc;
	void *qbase_addr;
	phys_addr_t qbase_phys_addr;
	/**< queue-page registers addr */
	void *reg_base;
	uint32_t qcontrol;
	/**< queue ctrl reg */
	uint32_t head_offset;
	uint32_t tail_offset;

	int lsb;
	/**< lsb region assigned to queue */
	unsigned long lsbmask;
	/**< lsb regions queue can access */
	unsigned long lsbmap[PTDMA_BITMAP_SIZE(LSB_COUNT)];
	/**< all lsb resources which queue is using */
	uint32_t sb_key;
	/**< lsb assigned for queue */
} __rte_cache_aligned;

/**
 * A structure describing a PTDMA device.
 */
struct ptdma_device {

	int id;
	/**< ptdma dev id on platform */
	struct ptdma_cmd_queue cmd_q[MAX_HW_QUEUES];
	/**< ptdma queue */
	int cmd_q_count;
	/**< no. of ptdma Queues */
	struct rte_pci_device pci;
	/**< ptdma pci identifier */
	int qidx;
	/**< current queue index */
} __rte_cache_aligned;

/* Passthru engine */

#define PTDMA_PT_BYTESWAP(p)      ((p)->pt.byteswap)
#define PTDMA_PT_BITWISE(p)       ((p)->pt.bitwise)

/**
 * passthru_bitwise - type of bitwise passthru operation
 *
 * @PTDMA_PASSTHRU_BITWISE_NOOP: no bitwise operation performed
 * @PTDMA_PASSTHRU_BITWISE_AND: perform bitwise AND of src with mask
 * @PTDMA_PASSTHRU_BITWISE_OR: perform bitwise OR of src with mask
 * @PTDMA_PASSTHRU_BITWISE_XOR: perform bitwise XOR of src with mask
 * @PTDMA_PASSTHRU_BITWISE_MASK: overwrite with mask
 */
enum ptdma_passthru_bitwise {
	PTDMA_PASSTHRU_BITWISE_NOOP = 0,
	PTDMA_PASSTHRU_BITWISE_AND,
	PTDMA_PASSTHRU_BITWISE_OR,
	PTDMA_PASSTHRU_BITWISE_XOR,
	PTDMA_PASSTHRU_BITWISE_MASK,
	PTDMA_PASSTHRU_BITWISE__LAST,
};

/**
 * ptdma_passthru_byteswap - type of byteswap passthru operation
 *
 * @PTDMA_PASSTHRU_BYTESWAP_NOOP: no byte swapping performed
 * @PTDMA_PASSTHRU_BYTESWAP_32BIT: swap bytes within 32-bit words
 * @PTDMA_PASSTHRU_BYTESWAP_256BIT: swap bytes within 256-bit words
 */
enum ptdma_passthru_byteswap {
	PTDMA_PASSTHRU_BYTESWAP_NOOP = 0,
	PTDMA_PASSTHRU_BYTESWAP_32BIT,
	PTDMA_PASSTHRU_BYTESWAP_256BIT,
	PTDMA_PASSTHRU_BYTESWAP__LAST,
};

/**
 * PTDMA passthru
 */
struct ptdma_passthru {
	phys_addr_t src_addr;
	phys_addr_t dest_addr;
	enum ptdma_passthru_bitwise bit_mod;
	enum ptdma_passthru_byteswap byte_swap;
	int len;
};

union ptdma_function {
	struct {
		uint16_t byteswap:2;
		uint16_t bitwise:3;
		uint16_t reflect:2;
		uint16_t rsvd:8;
	} pt;
	uint16_t raw;
};

/**
 * ptdma memory type
 */
enum ptdma_memtype {
	PTDMA_MEMTYPE_SYSTEM = 0,
	PTDMA_MEMTYPE_SB,
	PTDMA_MEMTYPE_LOCAL,
	PTDMA_MEMTYPE_LAST,
};

/*
 * descriptor for PTDMA commands
 * 8 32-bit words:
 * word 0: function; engine; control bits
 * word 1: length of source data
 * word 2: low 32 bits of source pointer
 * word 3: upper 16 bits of source pointer; source memory type
 * word 4: low 32 bits of destination pointer
 * word 5: upper 16 bits of destination pointer; destination memory type
 * word 6: reserved 32 bits
 * word 7: reserved 32 bits
 */

union dword0 {
	struct {
		uint32_t soc:1;
		uint32_t ioc:1;
		uint32_t rsvd1:1;
		uint32_t init:1;
		uint32_t eom:1;
		uint32_t function:15;
		uint32_t engine:4;
		uint32_t prot:1;
		uint32_t rsvd2:7;
	};
	uint32_t val;
};

struct dword3 {
	uint32_t  src_hi:16;
	uint32_t  src_mem:2;
	uint32_t  lsb_cxt_id:8;
	uint32_t  rsvd1:5;
	uint32_t  fixed:1;
};

struct dword5 {
	uint32_t  dst_hi:16;
	uint32_t  dst_mem:2;
	uint32_t  rsvd1:13;
	uint32_t  fixed:1;
};

struct ptdma_desc {
	union dword0 dw0;
	uint32_t length;
	uint32_t src_lo;
	struct dword3 dw3;
	uint32_t dst_lo;
	struct dword5 dw5;
	uint32_t rsvd1;
	uint32_t rsvd2;
};


static inline uint32_t
low32_value(unsigned long addr)
{
	return ((uint64_t)addr) & 0x0ffffffff;
}

static inline uint32_t
high32_value(unsigned long addr)
{
	return ((uint64_t)addr >> 32) & 0x00000ffff;
}

#endif

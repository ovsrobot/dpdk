/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2016-2021 Atomic Rules LLC
 */

#include <sys/stat.h>
#include <dlfcn.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_pci.h>
#include <bus_pci_driver.h>
#include <rte_bbdev.h>
#include <rte_bbdev_pmd.h>
#include <rte_bus_pci.h>
#include <rte_devargs.h>
#include <rte_malloc.h>
#include <rte_ring.h>

#include "ark_common.h"
#include "ark_bbdev_common.h"
#include "ark_bbdev_custom.h"
#include "ark_ddm.h"
#include "ark_mpu.h"
#include "ark_rqp.h"
#include "ark_udm.h"
#include "ark_bbext.h"

#define DRIVER_NAME baseband_ark

#define ARK_SYSCTRL_BASE  0x0
#define ARK_PKTGEN_BASE   0x10000
#define ARK_MPU_RX_BASE   0x20000
#define ARK_UDM_BASE      0x30000
#define ARK_MPU_TX_BASE   0x40000
#define ARK_DDM_BASE      0x60000
#define ARK_PKTDIR_BASE   0xa0000
#define ARK_PKTCHKR_BASE  0x90000
#define ARK_RCPACING_BASE 0xb0000
#define ARK_MPU_QOFFSET   0x00100

#define BB_ARK_TX_Q_FACTOR 4

#define ARK_RX_META_SIZE 32
#define ARK_RX_META_OFFSET (RTE_PKTMBUF_HEADROOM - ARK_RX_META_SIZE)
#define ARK_RX_MAX_NOCHAIN (RTE_MBUF_DEFAULT_DATAROOM)

static_assert(sizeof(struct ark_rx_meta) == ARK_RX_META_SIZE, "Unexpected struct size ark_rx_meta");
static_assert(sizeof(union ark_tx_meta) == 8, "Unexpected struct size ark_tx_meta");

static struct rte_pci_id pci_id_ark[] = {
	{RTE_PCI_DEVICE(AR_VENDOR_ID, 0x1015)},
	{RTE_PCI_DEVICE(AR_VENDOR_ID, 0x1016)},
	{.device_id = 0},
};

static const struct ark_dev_caps
ark_device_caps[] = {
		     SET_DEV_CAPS(0x1015, true, false),
		     SET_DEV_CAPS(0x1016, true, false),
		     {.device_id = 0,}
};


/* Forward declarations */
static const struct rte_bbdev_ops ark_bbdev_pmd_ops;

static int
check_for_ext(struct ark_bbdevice *ark)
{
	/* Get the env */
	const char *dllpath = getenv("ARK_BBEXT_PATH");

	if (dllpath == NULL) {
		ARK_BBDEV_LOG(DEBUG, "EXT NO dll path specified\n");
		return 0;
	}
	ARK_BBDEV_LOG(NOTICE, "EXT found dll path at %s\n", dllpath);

	/* Open and load the .so */
	ark->d_handle = dlopen(dllpath, RTLD_LOCAL | RTLD_LAZY);
	if (ark->d_handle == NULL) {
		ARK_BBDEV_LOG(ERR, "Could not load user extension %s\n",
			    dllpath);
		return -1;
	}
	ARK_BBDEV_LOG(DEBUG, "SUCCESS: loaded user extension %s\n",
			    dllpath);

	/* Get the entry points */
	ark->user_ext.dev_init =
		(void *(*)(struct rte_bbdev *, void *))
		dlsym(ark->d_handle, "rte_pmd_ark_bbdev_init");

	ark->user_ext.dev_uninit =
		(int (*)(struct rte_bbdev *, void *))
		dlsym(ark->d_handle, "rte_pmd_ark_dev_uninit");
	ark->user_ext.dev_start =
		(int (*)(struct rte_bbdev *, void *))
		dlsym(ark->d_handle, "rte_pmd_ark_bbdev_start");
	ark->user_ext.dev_stop =
		(int (*)(struct rte_bbdev *, void *))
		dlsym(ark->d_handle, "rte_pmd_ark_bbdev_stop");
	ark->user_ext.dequeue_ldpc_dec  =
		(int (*)(struct rte_bbdev *,
			 struct rte_bbdev_dec_op *,
			 uint32_t *,
			 void *))
		dlsym(ark->d_handle, "rte_pmd_ark_bbdev_dequeue_ldpc_dec");
	ark->user_ext.enqueue_ldpc_dec  =
		(int (*)(struct rte_bbdev *,
			 struct rte_bbdev_dec_op *,
			 uint32_t *,
			 uint8_t *,
			 void *))
		dlsym(ark->d_handle, "rte_pmd_ark_bbdev_enqueue_ldpc_dec");
	ark->user_ext.dequeue_ldpc_enc  =
		(int (*)(struct rte_bbdev *,
			 struct rte_bbdev_enc_op *,
			 uint32_t *,
			 void *))
		dlsym(ark->d_handle, "rte_pmd_ark_bbdev_dequeue_ldpc_enc");
	ark->user_ext.enqueue_ldpc_enc  =
		(int (*)(struct rte_bbdev *,
			 struct rte_bbdev_enc_op *,
			 uint32_t *,
			 uint8_t *,
			 void *))
		dlsym(ark->d_handle, "rte_pmd_ark_bbdev_enqueue_ldpc_enc");

	return 0;
}


/* queue */
struct ark_bbdev_queue {
	struct ark_bbdevice *ark_bbdev;

	struct rte_ring *active_ops;  /* Ring for processed packets */

	/* RX components */
	/* array of physical addresses of the mbuf data pointer */
	rte_iova_t *rx_paddress_q;
	struct ark_udm_t *udm;
	struct ark_mpu_t *rx_mpu;

	/* TX components */
	union ark_tx_meta *tx_meta_q;
	struct ark_mpu_t *tx_mpu;
	struct ark_ddm_t *ddm;

	/*  */
	uint32_t tx_queue_mask;
	uint32_t rx_queue_mask;

	int32_t rx_seed_index;		/* step 1 set with empty mbuf */
	int32_t rx_cons_index;		/* step 3 consumed by driver */

	/* 3 indexes to the paired data rings. */
	int32_t tx_prod_index;		/* where to put the next one */
	int32_t tx_free_index;		/* local copy of tx_cons_index */

	/* separate cache line -- written by FPGA -- RX announce */
	RTE_MARKER cacheline1 __rte_cache_min_aligned;
	volatile int32_t rx_prod_index; /* step 2 filled by FPGA */

	/* Separate cache line -- written by FPGA -- RX completion */
	RTE_MARKER cacheline2 __rte_cache_min_aligned;
	volatile int32_t tx_cons_index; /* hw is done, can be freed */
} __rte_cache_aligned;


static int
ark_bb_hw_q_setup(struct rte_bbdev *bbdev, uint16_t q_id, uint16_t queue_size)
{
	struct ark_bbdev_queue *q = bbdev->data->queues[q_id].queue_private;

	rte_iova_t queue_base;
	rte_iova_t phys_addr_q_base;
	rte_iova_t phys_addr_prod_index;
	rte_iova_t phys_addr_cons_index;

	if (ark_mpu_verify(q->rx_mpu, sizeof(rte_iova_t))) {
		ARK_BBDEV_LOG(ERR, "Illegal hw/sw configuration RX queue");
		return -1;
	}
	ARK_BBDEV_LOG(DEBUG, "ark_bb_q setup %u:%u",
		      bbdev->data->dev_id, q_id);

	/* RX MPU */
	phys_addr_q_base = rte_malloc_virt2iova(q->rx_paddress_q);
	/* Force TX mode on MPU to match bbdev behavior */
	ark_mpu_configure(q->rx_mpu, phys_addr_q_base, queue_size, 1);
	ark_mpu_start(q->rx_mpu);

	/* UDM */
	queue_base = rte_malloc_virt2iova(q);
	phys_addr_prod_index = queue_base +
		offsetof(struct ark_bbdev_queue, rx_prod_index);
	ark_udm_write_addr(q->udm, phys_addr_prod_index);
	ark_udm_queue_enable(q->udm, 1);

	/* TX MPU */
	phys_addr_q_base = rte_malloc_virt2iova(q->tx_meta_q);
	ark_mpu_configure(q->tx_mpu, phys_addr_q_base,
			  BB_ARK_TX_Q_FACTOR * queue_size, 1);
	ark_mpu_start(q->tx_mpu);

	/* DDM */
	phys_addr_cons_index = queue_base +
		offsetof(struct ark_bbdev_queue, tx_cons_index);
	ark_ddm_queue_setup(q->ddm, phys_addr_cons_index);
	ark_ddm_queue_reset_stats(q->ddm);

	return 0;
}



/* Setup a queue */
static int
ark_bb_q_setup(struct rte_bbdev *bbdev, uint16_t q_id,
	       const struct rte_bbdev_queue_conf *queue_conf)
{
	struct ark_bbdev_queue *q;
	struct ark_bbdevice *ark_bb =  bbdev->data->dev_private;

	const uint32_t queue_size = queue_conf->queue_size;
	const int socket_id = queue_conf->socket;
	const uint64_t pg_sz = sysconf(_SC_PAGESIZE);
	char ring_name[RTE_RING_NAMESIZE];

	/* Configuration checks */
	if (!rte_is_power_of_2(queue_size)) {
		ARK_BBDEV_LOG(ERR,
			      "Configuration queue size"
			      " must be power of two %u",
			      queue_size);
		return -EINVAL;
	}

	if (RTE_PKTMBUF_HEADROOM < ARK_RX_META_SIZE) {
		ARK_BBDEV_LOG(ERR,
			      "Error: Ark bbdev requires head room > %d bytes (%s)",
			      ARK_RX_META_SIZE, __func__);
		return -EINVAL;
	}

	/* Allocate the queue data structure. */
	q = rte_zmalloc_socket(RTE_STR(DRIVER_NAME), sizeof(*q),
			RTE_CACHE_LINE_SIZE, queue_conf->socket);
	if (q == NULL) {
		ARK_BBDEV_LOG(ERR, "Failed to allocate queue memory");
		return -ENOMEM;
	}
	bbdev->data->queues[q_id].queue_private = q;
	q->ark_bbdev = ark_bb;

	/* RING */
	snprintf(ring_name, RTE_RING_NAMESIZE, RTE_STR(DRIVER_NAME) "%u:%u",
		 bbdev->data->dev_id, q_id);
	q->active_ops = rte_ring_create(ring_name,
					queue_size,
					queue_conf->socket,
					RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (q->active_ops == NULL) {
		ARK_BBDEV_LOG(ERR, "Failed to create ring");
		goto free_all;
	}

	q->rx_queue_mask = queue_size - 1;
	q->tx_queue_mask = (BB_ARK_TX_Q_FACTOR * queue_size) - 1;

	/* Each mbuf requires 2 to 4 objects, factor by BB_ARK_TX_Q_FACTOR */
	q->tx_meta_q =
		rte_zmalloc_socket("Ark_bb_txqueue meta",
				   queue_size * BB_ARK_TX_Q_FACTOR *
				   sizeof(union ark_tx_meta),
				   pg_sz,
				   socket_id);

	if (q->tx_meta_q == 0) {
		ARK_BBDEV_LOG(ERR, "Failed to allocate "
			      "queue memory in %s", __func__);
		goto free_all;
	}

	q->ddm = RTE_PTR_ADD(ark_bb->ddm.v, q_id * ARK_DDM_QOFFSET);
	q->tx_mpu = RTE_PTR_ADD(ark_bb->mputx.v, q_id * ARK_MPU_QOFFSET);

	q->rx_paddress_q =
		rte_zmalloc_socket("ark_bb_rx_paddress_q",
				   queue_size * sizeof(rte_iova_t),
				   pg_sz,
				   socket_id);

	if (q->rx_paddress_q == 0) {
		ARK_BBDEV_LOG(ERR,
			      "Failed to allocate queue memory in %s",
			      __func__);
		goto free_all;
	}
	q->udm = RTE_PTR_ADD(ark_bb->udm.v, q_id * ARK_UDM_QOFFSET);
	q->rx_mpu = RTE_PTR_ADD(ark_bb->mpurx.v, q_id * ARK_MPU_QOFFSET);

	/* Structure have been configured, set the hardware */
	return ark_bb_hw_q_setup(bbdev, q_id, queue_size);

free_all:
	rte_free(q->tx_meta_q);
	rte_free(q->rx_paddress_q);
	rte_free(q);
	return -EFAULT;
}


/* Release queue */
static int
ark_bb_q_release(struct rte_bbdev *bbdev, uint16_t q_id)
{
	struct ark_bbdev_queue *q = bbdev->data->queues[q_id].queue_private;

	ark_mpu_dump(q->rx_mpu, "rx_MPU release", q_id);
	ark_mpu_dump(q->tx_mpu, "tx_MPU release", q_id);

	rte_ring_free(q->active_ops);
	rte_free(q->tx_meta_q);
	rte_free(q->rx_paddress_q);
	rte_free(q);
	bbdev->data->queues[q_id].queue_private = NULL;

	ARK_BBDEV_LOG(DEBUG, "released device queue %u:%u",
		      bbdev->data->dev_id, q_id);
	return 0;
}

static int
ark_bbdev_start(struct rte_bbdev *bbdev)
{
	struct ark_bbdevice *ark_bb = bbdev->data->dev_private;

	ARK_BBDEV_LOG(DEBUG, "Starting device %u", bbdev->data->dev_id);
	if (ark_bb->started)
		return 0;

	/* User start hook */
	if (ark_bb->user_ext.dev_start)
		ark_bb->user_ext.dev_start(bbdev,
					   ark_bb->user_data);

	ark_bb->started = 1;

	if (ark_bb->start_pg)
		ark_pktchkr_run(ark_bb->pc);

	if (ark_bb->start_pg) {
		pthread_t thread;

		/* Delay packet generator start allow the hardware to be ready
		 * This is only used for sanity checking with internal generator
		 */
		if (pthread_create(&thread, NULL,
				   ark_pktgen_delay_start, ark_bb->pg)) {
			ARK_BBDEV_LOG(ERR, "Could not create pktgen "
				    "starter thread");
			return -1;
		}
	}

	return 0;
}


static void
ark_bbdev_stop(struct rte_bbdev *bbdev)
{
	struct ark_bbdevice *ark_bb = bbdev->data->dev_private;

	ARK_BBDEV_LOG(DEBUG, "Stopping device %u", bbdev->data->dev_id);

	if (!ark_bb->started)
		return;

	/* Stop the packet generator */
	if (ark_bb->start_pg)
		ark_pktgen_pause(ark_bb->pg);

	/* STOP RX Side */
	ark_udm_dump_stats(ark_bb->udm.v, "Post stop");

	/* Stop the packet checker if it is running */
	if (ark_bb->start_pg) {
		ark_pktchkr_dump_stats(ark_bb->pc);
		ark_pktchkr_stop(ark_bb->pc);
	}

	/* User stop hook */
	if (ark_bb->user_ext.dev_stop)
		ark_bb->user_ext.dev_stop(bbdev,
					  ark_bb->user_data);

}


static int
ark_bb_q_start(struct rte_bbdev *bbdev, uint16_t q_id)
{
	struct ark_bbdev_queue *q = bbdev->data->queues[q_id].queue_private;
	ARK_BBDEV_LOG(DEBUG, "ark_bb_q start %u:%u", bbdev->data->dev_id, q_id);
	ark_ddm_queue_enable(q->ddm, 1);
	ark_udm_queue_enable(q->udm, 1);
	ark_mpu_start(q->tx_mpu);
	ark_mpu_start(q->rx_mpu);
	return 0;
}
static int
ark_bb_q_stop(struct rte_bbdev *bbdev, uint16_t q_id)
{
	struct ark_bbdev_queue *q = bbdev->data->queues[q_id].queue_private;
	int cnt = 0;

	ARK_BBDEV_LOG(DEBUG, "ark_bb_q stop %u:%u", bbdev->data->dev_id, q_id);

	while (q->tx_cons_index != q->tx_prod_index) {
		usleep(100);
		if (cnt++ > 10000) {
			fprintf(stderr, "XXXX %s(%u, %u %u) %d Failured\n", __func__, q_id,
				q->tx_cons_index, q->tx_prod_index,
				(int32_t) (q->tx_prod_index - q->tx_cons_index));
			return -1;
		}
	}

	ark_mpu_stop(q->tx_mpu);
	ark_mpu_stop(q->rx_mpu);
	ark_udm_queue_enable(q->udm, 0);
	ark_ddm_queue_enable(q->ddm, 0);
	return 0;
}




/* ************************************************************************* */
/* Common function for all enqueue and dequeue ops */
static inline void
ark_bb_enqueue_desc_fill(struct ark_bbdev_queue *q,
			 struct rte_mbuf *mbuf,
			 uint16_t offset, /* Extra offset */
			 uint8_t  flags,
			 uint32_t *meta,
			 uint8_t  meta_cnt /* 0, 1 or 2 */
			 )
{
	union ark_tx_meta *tx_meta;
	int32_t tx_idx;
	uint8_t m;

	/* Header */
	tx_idx = q->tx_prod_index & q->tx_queue_mask;
	tx_meta = &q->tx_meta_q[tx_idx];
	tx_meta->data_len = rte_pktmbuf_data_len(mbuf) - offset;
	tx_meta->flags = flags;
	tx_meta->meta_cnt = meta_cnt;
	tx_meta->user1 = *meta++;
	q->tx_prod_index++;

	for (m = 0; m < meta_cnt; m++) {
		tx_idx = q->tx_prod_index & q->tx_queue_mask;
		tx_meta = &q->tx_meta_q[tx_idx];
		tx_meta->usermeta0 = *meta++;
		tx_meta->usermeta1 = *meta++;
		q->tx_prod_index++;
	}

	tx_idx = q->tx_prod_index & q->tx_queue_mask;
	tx_meta = &q->tx_meta_q[tx_idx];
	tx_meta->physaddr = rte_mbuf_data_iova(mbuf) + offset;
	q->tx_prod_index++;
}

static inline void
ark_bb_enqueue_segmented_pkt(struct ark_bbdev_queue *q,
			     struct rte_mbuf *mbuf,
			     uint16_t offset,
			     uint32_t *meta, uint8_t meta_cnt)
{
	struct rte_mbuf *next;
	uint8_t flags = ARK_DDM_SOP;

	while (mbuf != NULL) {
		next = mbuf->next;
		flags |= (next == NULL) ? ARK_DDM_EOP : 0;

		ark_bb_enqueue_desc_fill(q, mbuf, offset, flags,
					 meta, meta_cnt);

		flags &= ~ARK_DDM_SOP;	/* drop SOP flags */
		meta_cnt = 0;
		offset = 0;

		mbuf = next;
	}
}

static inline int
ark_bb_enqueue_common(struct ark_bbdev_queue *q,
		      struct rte_mbuf *m_in, struct rte_mbuf *m_out,
		      uint16_t offset,
		      uint32_t *meta, uint8_t meta_cnt)
{
	int32_t free_queue_space;
	int32_t rx_idx;

	/* TX side limit */
	free_queue_space = q->tx_queue_mask -
		(q->tx_prod_index - q->tx_free_index);
	if (unlikely(free_queue_space < (2 + (2 * m_in->nb_segs))))
		return 1;

	/* RX side limit */
	free_queue_space = q->rx_queue_mask -
		(q->rx_seed_index - q->rx_cons_index);
	if (unlikely(free_queue_space < m_out->nb_segs))
		return 1;

	if (unlikely(m_in->nb_segs > 1))
		ark_bb_enqueue_segmented_pkt(q, m_in, offset, meta, meta_cnt);
	else
		ark_bb_enqueue_desc_fill(q, m_in, offset,
					 ARK_DDM_SOP | ARK_DDM_EOP,
					 meta, meta_cnt);

	/* We assume that the return mubf has exactly enough segments for
	 * return data, which is 2048 bytes per segment.
	 */
	do {
		rx_idx = q->rx_seed_index & q->rx_queue_mask;
		q->rx_paddress_q[rx_idx] = m_out->buf_iova;
		q->rx_seed_index++;
		m_out = m_out->next;
	} while (m_out);

	return 0;
}

static inline void
ark_bb_enqueue_finalize(struct rte_bbdev_queue_data *q_data,
			struct ark_bbdev_queue *q,
			void **ops,
			uint16_t nb_ops, uint16_t nb)
{
	/* BBDEV global stats */
	/* These are not really errors, not sure why bbdev counts these. */
	q_data->queue_stats.enqueue_err_count += nb_ops - nb;
	q_data->queue_stats.enqueued_count += nb;

	/* Notify HW that  */
	if (unlikely(nb == 0))
		return;

	ark_mpu_set_producer(q->tx_mpu, q->tx_prod_index);
	ark_mpu_set_producer(q->rx_mpu, q->rx_seed_index);

	/* Queue info for dequeue-side processing */
	rte_ring_enqueue_burst(q->active_ops,
			       (void **)ops, nb, NULL);
}

static int
ark_bb_dequeue_segmented(struct rte_mbuf *mbuf0,
			 int32_t *prx_cons_index,
			 uint16_t pkt_len
			 )
{
	struct rte_mbuf *mbuf;
	uint16_t data_len;
	uint16_t remaining;
	uint16_t segments = 1;

	data_len = RTE_MIN(pkt_len, RTE_MBUF_DEFAULT_DATAROOM);
	remaining = pkt_len - data_len;

	mbuf = mbuf0;
	mbuf0->data_len = data_len;
	while (remaining) {
		segments += 1;
		mbuf = mbuf->next;
		if (unlikely(mbuf == 0)) {
			ARK_BBDEV_LOG(CRIT, "Expected chained mbuf with "
				      "at least %d segments for dequeue "
				      "of packet length %d",
				      segments, pkt_len);
			return 1;
		}

		data_len = RTE_MIN(remaining,
				   RTE_MBUF_DEFAULT_DATAROOM);
		remaining -= data_len;

		mbuf->data_len = data_len;
		*prx_cons_index += 1;
	}

	if (mbuf->next != 0) {
		ARK_BBDEV_LOG(CRIT, "Expected chained mbuf with "
			      "at exactly %d segments for dequeue "
			      "of packet length %d. Found %d "
			      "segments",
			      segments, pkt_len, mbuf0->nb_segs);
		return 1;
	}
	return 0;
}

/* ************************************************************************* */
/* LDPC Decode ops */
static int16_t
ark_bb_enqueue_ldpc_dec_one_op(struct ark_bbdev_queue *q,
			       struct rte_bbdev_dec_op *this_op)
{
	struct rte_bbdev_op_ldpc_dec *ldpc_dec_op = &this_op->ldpc_dec;
	struct rte_mbuf *m_in = ldpc_dec_op->input.data;
	struct rte_mbuf *m_out = ldpc_dec_op->hard_output.data;
	uint16_t offset = ldpc_dec_op->input.offset;
	uint32_t meta[5] = {0};
	uint8_t meta_cnt = 0;

	if (q->ark_bbdev->user_ext.enqueue_ldpc_dec) {
		if (q->ark_bbdev->user_ext.enqueue_ldpc_dec(q->ark_bbdev->bbdev,
							    this_op,
							    meta,
							    &meta_cnt,
							    q->ark_bbdev->user_data)) {
			ARK_BBDEV_LOG(ERR, "%s failed", __func__);
			return 1;
		}
	}

	return ark_bb_enqueue_common(q, m_in, m_out, offset, meta, meta_cnt);
}

/* Enqueue LDPC Decode -- burst */
static uint16_t
ark_bb_enqueue_ldpc_dec_ops(struct rte_bbdev_queue_data *q_data,
			    struct rte_bbdev_dec_op **ops, uint16_t nb_ops)
{
	struct ark_bbdev_queue *q = q_data->queue_private;
	unsigned int max_enq;
	uint16_t nb;

	max_enq = rte_ring_free_count(q->active_ops);
	max_enq = RTE_MIN(max_enq, nb_ops);
	for (nb = 0; nb < max_enq; nb++) {
		if (ark_bb_enqueue_ldpc_dec_one_op(q, ops[nb]))
			break;
	}

	ark_bb_enqueue_finalize(q_data, q, (void **)ops, nb_ops, nb);
	return nb;
}


/* ************************************************************************* */
/* Dequeue LDPC Decode -- burst */
static uint16_t
ark_bb_dequeue_ldpc_dec_ops(struct rte_bbdev_queue_data *q_data,
			    struct rte_bbdev_dec_op **ops, uint16_t nb_ops)
{
	struct ark_bbdev_queue *q = q_data->queue_private;
	struct rte_mbuf *mbuf;
	struct rte_bbdev_dec_op *this_op;
	struct ark_rx_meta *meta;
	uint32_t *usermeta;

	uint16_t nb = 0;
	int32_t prod_index = q->rx_prod_index;
	int32_t cons_index = q->rx_cons_index;

	q->tx_free_index = q->tx_cons_index;

	while ((prod_index - cons_index) > 0) {
		if (rte_ring_dequeue(q->active_ops, (void **)&this_op)) {
			ARK_BBDEV_LOG(ERR, "%s data ready but no op!",
				      __func__);
			q_data->queue_stats.dequeue_err_count += 1;
			break;
		}
		ops[nb] = this_op;

		mbuf = this_op->ldpc_dec.hard_output.data;

		/* META DATA embedded in headroom */
		meta = RTE_PTR_ADD(mbuf->buf_addr, ARK_RX_META_OFFSET);

		mbuf->pkt_len = meta->pkt_len;
		mbuf->data_len = meta->pkt_len;

		if (unlikely(meta->pkt_len > ARK_RX_MAX_NOCHAIN)) {
			if (ark_bb_dequeue_segmented(mbuf, &cons_index,
						     meta->pkt_len))
				q_data->queue_stats.dequeue_err_count += 1;
		} else if (mbuf->next != 0) {
			ARK_BBDEV_LOG(CRIT, "Expected mbuf with "
				      "at exactly 1 segments for dequeue "
				      "of packet length %d. Found %d "
				      "segments",
				      meta->pkt_len, mbuf->nb_segs);
			q_data->queue_stats.dequeue_err_count += 1;
		}

		usermeta = meta->user_meta;

		/* User's meta move from Arkville HW to bbdev OP */
		if (q->ark_bbdev->user_ext.dequeue_ldpc_dec) {
			if (q->ark_bbdev->user_ext.dequeue_ldpc_dec(q->ark_bbdev->bbdev,
								    this_op,
								    usermeta,
								    q->ark_bbdev->user_data)) {
				ARK_BBDEV_LOG(ERR, "%s failed", __func__);
				return 1;
			}
		}

		nb++;
		cons_index++;
		if (nb >= nb_ops)
			break;
	}

	q->rx_cons_index = cons_index;

	/* BBdev stats */
	q_data->queue_stats.dequeued_count += nb;

	return nb;
}

/**************************************************************************/
/* Enqueue LDPC Encode */
static int16_t
ark_bb_enqueue_ldpc_enc_one_op(struct ark_bbdev_queue *q,
			       struct rte_bbdev_enc_op *this_op)
{
	struct rte_bbdev_op_ldpc_enc *ldpc_enc_op = &this_op->ldpc_enc;
	struct rte_mbuf *m_in = ldpc_enc_op->input.data;
	struct rte_mbuf *m_out = ldpc_enc_op->output.data;
	uint16_t offset = ldpc_enc_op->input.offset;
	uint32_t meta[5] = {0};
	uint8_t meta_cnt = 0;

	/* User's meta move from bbdev op to Arkville HW */
	if (q->ark_bbdev->user_ext.enqueue_ldpc_enc) {
		if (q->ark_bbdev->user_ext.enqueue_ldpc_enc(q->ark_bbdev->bbdev,
							    this_op,
							    meta,
							    &meta_cnt,
							    q->ark_bbdev->user_data)) {
			ARK_BBDEV_LOG(ERR, "%s failed", __func__);
			return 1;
		}
	}

	return ark_bb_enqueue_common(q, m_in, m_out, offset, meta, meta_cnt);
}

/* Enqueue LDPC Encode -- burst */
static uint16_t
ark_bb_enqueue_ldpc_enc_ops(struct rte_bbdev_queue_data *q_data,
			    struct rte_bbdev_enc_op **ops, uint16_t nb_ops)
{
	struct ark_bbdev_queue *q = q_data->queue_private;
	unsigned int max_enq;
	uint16_t nb;

	max_enq = rte_ring_free_count(q->active_ops);
	max_enq = RTE_MIN(max_enq, nb_ops);
	for (nb = 0; nb < max_enq; nb++) {
		if (ark_bb_enqueue_ldpc_enc_one_op(q, ops[nb]))
			break;
	}

	ark_bb_enqueue_finalize(q_data, q, (void **)ops, nb_ops, nb);
	return nb;
}

/* Dequeue LDPC Encode -- burst */
static uint16_t
ark_bb_dequeue_ldpc_enc_ops(struct rte_bbdev_queue_data *q_data,
			    struct rte_bbdev_enc_op **ops, uint16_t nb_ops)
{
	struct ark_bbdev_queue *q = q_data->queue_private;
	struct rte_mbuf *mbuf;
	struct rte_bbdev_enc_op *this_op;
	struct ark_rx_meta *meta;
	uint32_t *usermeta;

	uint16_t nb = 0;
	int32_t prod_index = q->rx_prod_index;
	int32_t cons_index = q->rx_cons_index;

	q->tx_free_index = q->tx_cons_index;

	while ((prod_index - cons_index) > 0) {
		if (rte_ring_dequeue(q->active_ops, (void **)&this_op)) {
			ARK_BBDEV_LOG(ERR, "%s data ready but no op!",
				      __func__);
			q_data->queue_stats.dequeue_err_count += 1;
			break;
		}
		ops[nb] = this_op;

		mbuf = this_op->ldpc_enc.output.data;

		/* META DATA embedded in headroom */
		meta = RTE_PTR_ADD(mbuf->buf_addr, ARK_RX_META_OFFSET);

		mbuf->pkt_len = meta->pkt_len;
		mbuf->data_len = meta->pkt_len;
		usermeta = meta->user_meta;

		if (unlikely(meta->pkt_len > ARK_RX_MAX_NOCHAIN)) {
			if (ark_bb_dequeue_segmented(mbuf, &cons_index,
						     meta->pkt_len))
				q_data->queue_stats.dequeue_err_count += 1;
		} else if (mbuf->next != 0) {
			ARK_BBDEV_LOG(CRIT, "Expected mbuf with "
				      "at exactly 1 segments for dequeue "
				      "of packet length %d. Found %d "
				      "segments",
				      meta->pkt_len, mbuf->nb_segs);
			q_data->queue_stats.dequeue_err_count += 1;
		}

		/* User's meta move from Arkville HW to bbdev OP */
		if (q->ark_bbdev->user_ext.dequeue_ldpc_enc) {
			if (q->ark_bbdev->user_ext.dequeue_ldpc_enc(q->ark_bbdev->bbdev,
								    this_op,
								    usermeta,
								    q->ark_bbdev->user_data)) {
				ARK_BBDEV_LOG(ERR, "%s failed", __func__);
				return 1;
			}
		}

		nb++;
		cons_index++;
		if (nb >= nb_ops)
			break;
	}

	q->rx_cons_index = cons_index;

	/* BBdev stats */
	q_data->queue_stats.dequeued_count += nb;

	return nb;
}


/**************************************************************************/
/*
 *Initial device hardware configuration when device is opened
 * setup the DDM, and UDM; called once per PCIE device
 */
static int
ark_bb_config_device(struct ark_bbdevice *ark_bb)
{
	uint16_t num_q, i;
	struct ark_mpu_t *mpu;

	/*
	 * Make sure that the packet director, generator and checker are in a
	 * known state
	 */
	ark_bb->start_pg = 0;
	ark_bb->pg = ark_pktgen_init(ark_bb->pktgen.v, 0, 1);
	if (ark_bb->pg == NULL)
		return -1;
	ark_pktgen_reset(ark_bb->pg);
	ark_bb->pc = ark_pktchkr_init(ark_bb->pktchkr.v, 0, 1);
	if (ark_bb->pc == NULL)
		return -1;
	ark_pktchkr_stop(ark_bb->pc);
	ark_bb->pd = ark_pktdir_init(ark_bb->pktdir.v);
	if (ark_bb->pd == NULL)
		return -1;

	/* Verify HW */
	if (ark_udm_verify(ark_bb->udm.v))
		return -1;
	if (ark_ddm_verify(ark_bb->ddm.v))
		return -1;

	/* MPU reset */
	mpu = ark_bb->mpurx.v;
	num_q = ark_api_num_queues(mpu);
	ark_bb->max_nb_queues = num_q;

	for (i = 0; i < num_q; i++) {
		ark_mpu_reset(mpu);
		mpu = RTE_PTR_ADD(mpu, ARK_MPU_QOFFSET);
	}

	ark_udm_configure(ark_bb->udm.v,
			  RTE_PKTMBUF_HEADROOM,
			  RTE_MBUF_DEFAULT_DATAROOM);

	mpu = ark_bb->mputx.v;
	num_q = ark_api_num_queues(mpu);
	for (i = 0; i < num_q; i++) {
		ark_mpu_reset(mpu);
		mpu = RTE_PTR_ADD(mpu, ARK_MPU_QOFFSET);
	}

	ark_rqp_stats_reset(ark_bb->rqpacing);

	ARK_BBDEV_LOG(INFO, "packet director set to 0x%x", ark_bb->pkt_dir_v);
	ark_pktdir_setup(ark_bb->pd, ark_bb->pkt_dir_v);

	if (ark_bb->pkt_gen_args[0]) {
		ARK_BBDEV_LOG(INFO, "Setting up the packet generator");
		ark_pktgen_parse(ark_bb->pkt_gen_args);
		ark_pktgen_reset(ark_bb->pg);
		ark_pktgen_setup(ark_bb->pg);
		ark_bb->start_pg = 1;
	}

	return 0;
}

static int
ark_bbdev_init(struct rte_bbdev *bbdev, struct rte_pci_driver *pci_drv)
{
	struct ark_bbdevice *ark_bb = bbdev->data->dev_private;
	struct rte_pci_device *pci_dev = RTE_DEV_TO_PCI(bbdev->device);
	bool rqpacing = false;
	int p;
	ark_bb->bbdev = bbdev;

	RTE_SET_USED(pci_drv);

	ark_bb->bar0 = (uint8_t *)pci_dev->mem_resource[0].addr;
	ark_bb->a_bar = (uint8_t *)pci_dev->mem_resource[2].addr;

	ark_bb->sysctrl.v  = (void *)&ark_bb->bar0[ARK_SYSCTRL_BASE];
	ark_bb->mpurx.v  = (void *)&ark_bb->bar0[ARK_MPU_RX_BASE];
	ark_bb->udm.v  = (void *)&ark_bb->bar0[ARK_UDM_BASE];
	ark_bb->mputx.v  = (void *)&ark_bb->bar0[ARK_MPU_TX_BASE];
	ark_bb->ddm.v  = (void *)&ark_bb->bar0[ARK_DDM_BASE];
	ark_bb->pktdir.v  = (void *)&ark_bb->bar0[ARK_PKTDIR_BASE];
	ark_bb->pktgen.v  = (void *)&ark_bb->bar0[ARK_PKTGEN_BASE];
	ark_bb->pktchkr.v  = (void *)&ark_bb->bar0[ARK_PKTCHKR_BASE];

	p = 0;
	while (ark_device_caps[p].device_id != 0) {
		if (pci_dev->id.device_id == ark_device_caps[p].device_id) {
			rqpacing = ark_device_caps[p].caps.rqpacing;
			break;
		}
		p++;
	}

	if (rqpacing)
		ark_bb->rqpacing =
			(struct ark_rqpace_t *)(ark_bb->bar0 + ARK_RCPACING_BASE);
	else
		ark_bb->rqpacing = NULL;

	/* Check to see if there is an extension that we need to load */
	if (check_for_ext(ark_bb))
		return -1;

	ark_bb->started = 0;

	ARK_BBDEV_LOG(INFO, "Sys Ctrl Const = 0x%x  HW Commit_ID: %08x",
		      ark_bb->sysctrl.t32[4],
		      rte_be_to_cpu_32(ark_bb->sysctrl.t32[0x20 / 4]));
	ARK_BBDEV_LOG(INFO, "Arkville HW Commit_ID: %08x",
		    rte_be_to_cpu_32(ark_bb->sysctrl.t32[0x20 / 4]));

	/* If HW sanity test fails, return an error */
	if (ark_bb->sysctrl.t32[4] != 0xcafef00d) {
		ARK_BBDEV_LOG(ERR,
			      "HW Sanity test has failed, expected constant"
			      " 0x%x, read 0x%x (%s)",
			      0xcafef00d,
			      ark_bb->sysctrl.t32[4], __func__);
		return -1;
	}

	return ark_bb_config_device(ark_bb);
}

static int
ark_bbdev_uninit(struct rte_bbdev *bbdev)
{
	struct ark_bbdevice *ark_bb = bbdev->data->dev_private;

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	ark_pktgen_uninit(ark_bb->pg);
	ark_pktchkr_uninit(ark_bb->pc);

	return 0;
}

static int
ark_bbdev_probe(struct rte_pci_driver *pci_drv,
		struct rte_pci_device *pci_dev)
{
	struct rte_bbdev *bbdev = NULL;
	char dev_name[RTE_BBDEV_NAME_MAX_LEN];
	struct ark_bbdevice *ark_bb;

	if (pci_dev == NULL)
		return -EINVAL;

	rte_pci_device_name(&pci_dev->addr, dev_name, sizeof(dev_name));

	/* Allocate memory to be used privately by drivers */
	bbdev = rte_bbdev_allocate(pci_dev->device.name);
	if (bbdev == NULL)
		return -ENODEV;

	/* allocate device private memory */
	bbdev->data->dev_private = rte_zmalloc_socket(dev_name,
			sizeof(struct ark_bbdevice),
			RTE_CACHE_LINE_SIZE,
			pci_dev->device.numa_node);

	if (bbdev->data->dev_private == NULL) {
		ARK_BBDEV_LOG(CRIT,
				"Allocate of %zu bytes for device \"%s\" failed",
				sizeof(struct ark_bbdevice), dev_name);
				rte_bbdev_release(bbdev);
			return -ENOMEM;
	}
	ark_bb = bbdev->data->dev_private;
	/* Initialize ark_bb */
	ark_bb->pkt_dir_v = 0x00110110;

	/* Fill HW specific part of device structure */
	bbdev->device = &pci_dev->device;
	bbdev->intr_handle = NULL;
	bbdev->data->socket_id = pci_dev->device.numa_node;
	bbdev->dev_ops = &ark_bbdev_pmd_ops;
	if (pci_dev->device.devargs)
		parse_ark_bbdev_params(pci_dev->device.devargs->args, ark_bb);


	/* Device specific initialization */
	if (ark_bbdev_init(bbdev, pci_drv))
		return -EIO;
	if (ark_bbdev_start(bbdev))
		return -EIO;

	/* Core operations LDPC encode amd decode */
	bbdev->enqueue_ldpc_enc_ops = ark_bb_enqueue_ldpc_enc_ops;
	bbdev->dequeue_ldpc_enc_ops = ark_bb_dequeue_ldpc_enc_ops;
	bbdev->enqueue_ldpc_dec_ops = ark_bb_enqueue_ldpc_dec_ops;
	bbdev->dequeue_ldpc_dec_ops = ark_bb_dequeue_ldpc_dec_ops;

	ARK_BBDEV_LOG(DEBUG, "bbdev id = %u [%s]",
		      bbdev->data->dev_id, dev_name);

	return 0;
}

/* Uninitialize device */
static int
ark_bbdev_remove(struct rte_pci_device *pci_dev)
{
	struct rte_bbdev *bbdev;
	int ret;

	if (pci_dev == NULL)
		return -EINVAL;

	/* Find device */
	bbdev = rte_bbdev_get_named_dev(pci_dev->device.name);
	if (bbdev == NULL) {
		ARK_BBDEV_LOG(CRIT,
				"Couldn't find HW dev \"%s\" to Uninitialize it",
				pci_dev->device.name);
		return -ENODEV;
	}

	/* Arkville device close */
	ark_bbdev_uninit(bbdev);
	rte_free(bbdev->data->dev_private);

	/* Close device */
	ret = rte_bbdev_close(bbdev->data->dev_id);
	if (ret < 0)
		ARK_BBDEV_LOG(ERR,
				"Device %i failed to close during remove: %i",
				bbdev->data->dev_id, ret);

	return rte_bbdev_release(bbdev);
}

/* Operation for the PMD */
static const struct rte_bbdev_ops ark_bbdev_pmd_ops = {
	.info_get = ark_bbdev_info_get,
	.start = ark_bbdev_start,
	.stop = ark_bbdev_stop,
	.queue_setup = ark_bb_q_setup,
	.queue_release = ark_bb_q_release,
	.queue_start = ark_bb_q_start,
	.queue_stop = ark_bb_q_stop,
};

static struct rte_pci_driver ark_bbdev_pmd_drv = {
	.probe = ark_bbdev_probe,
	.remove = ark_bbdev_remove,
	.id_table = pci_id_ark,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING
};

RTE_PMD_REGISTER_PCI(DRIVER_NAME, ark_bbdev_pmd_drv);
RTE_PMD_REGISTER_PCI_TABLE(DRIVER_NAME, pci_id_ark);
RTE_PMD_REGISTER_PARAM_STRING(DRIVER_NAME,
			      ARK_BBDEV_PKTGEN_ARG "=<filename> "
			      ARK_BBDEV_PKTCHKR_ARG "=<filename> "
			      ARK_BBDEV_PKTDIR_ARG "=<bitmap>"
			      );

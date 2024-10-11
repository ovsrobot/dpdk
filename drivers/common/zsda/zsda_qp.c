/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 ZTE Corporation
 */

#include <stdint.h>

#include <rte_malloc.h>

#include "zsda_common.h"
#include "zsda_logs.h"
#include "zsda_device.h"
#include "zsda_qp.h"

#define RING_DIR_TX 0
#define RING_DIR_RX 1

struct ring_size {
	uint16_t tx_msg_size;
	uint16_t rx_msg_size;
};
uint8_t zsda_num_used_qps;

struct ring_size zsda_qp_hw_ring_size[ZSDA_MAX_SERVICES] = {
	[ZSDA_SERVICE_SYMMETRIC_ENCRYPT] = {128, 16},
	[ZSDA_SERVICE_SYMMETRIC_DECRYPT] = {128, 16},
	[ZSDA_SERVICE_COMPRESSION] = {32, 16},
	[ZSDA_SERVICE_DECOMPRESSION] = {32, 16},
	[ZSDA_SERVICE_HASH_ENCODE] = {32, 16},
};

static void
zsda_set_queue_head_tail(const struct zsda_pci_device *zsda_pci_dev,
			 const uint8_t qid)
{
	struct rte_pci_device *pci_dev =
		zsda_devs[zsda_pci_dev->zsda_dev_id].pci_dev;
	uint8_t *mmio_base = pci_dev->mem_resource[0].addr;

	ZSDA_CSR_WRITE32(mmio_base + IO_DB_INITIAL_CONFIG + (qid * 4),
			 SET_HEAD_INTI);
}

static int
zsda_get_queue_cfg_by_id(const struct zsda_pci_device *zsda_pci_dev,
			 const uint8_t qid, struct qinfo *qcfg)
{
	struct zsda_admin_req_qcfg req = {0};
	struct zsda_admin_resp_qcfg resp = {0};
	int ret = 0;
	struct rte_pci_device *pci_dev =
		zsda_devs[zsda_pci_dev->zsda_dev_id].pci_dev;

	if (qid >= MAX_QPS_ON_FUNCTION) {
		ZSDA_LOG(ERR, "qid beyond limit!");
		return ZSDA_FAILED;
	}

	zsda_admin_msg_init(pci_dev);
	req.msg_type = ZSDA_ADMIN_QUEUE_CFG_REQ;
	req.qid = qid;

	ret = zsda_send_admin_msg(pci_dev, &req, sizeof(req));
	if (ret) {
		ZSDA_LOG(ERR, "Failed! Send msg");
		return ret;
	}

	ret = zsda_recv_admin_msg(pci_dev, &resp, sizeof(resp));
	if (ret) {
		ZSDA_LOG(ERR, "Failed! Receive msg");
		return ret;
	}

	memcpy(qcfg, &resp.qcfg, sizeof(*qcfg));

	return ZSDA_SUCCESS;
}


int
zsda_get_queue_cfg(struct zsda_pci_device *zsda_pci_dev)
{
	uint8_t i;
	uint32_t index;
	enum zsda_service_type type;
	struct zsda_qp_hw *zsda_hw_qps = zsda_pci_dev->zsda_hw_qps;
	struct qinfo qcfg = {0};
	int ret = 0;

	for (i = 0; i < zsda_num_used_qps; i++) {
		zsda_set_queue_head_tail(zsda_pci_dev, i);
		ret = zsda_get_queue_cfg_by_id(zsda_pci_dev, i, &qcfg);
		type = qcfg.q_type;
		if (ret) {
			ZSDA_LOG(ERR, "get queue cfg!");
			return ret;
		}
		if (type >= ZSDA_SERVICE_INVALID)
			continue;

		index = zsda_pci_dev->zsda_qp_hw_num[type];
		zsda_hw_qps[type].data[index].used = true;
		zsda_hw_qps[type].data[index].tx_ring_num = i;
		zsda_hw_qps[type].data[index].rx_ring_num = i;
		zsda_hw_qps[type].data[index].tx_msg_size =
			zsda_qp_hw_ring_size[type].tx_msg_size;
		zsda_hw_qps[type].data[index].rx_msg_size =
			zsda_qp_hw_ring_size[type].rx_msg_size;

		zsda_pci_dev->zsda_qp_hw_num[type]++;
	}

	return ret;
}


static uint8_t
zsda_get_num_used_qps(const struct rte_pci_device *pci_dev)
{
	uint8_t *mmio_base = pci_dev->mem_resource[0].addr;
	uint8_t num_used_qps;

	num_used_qps = ZSDA_CSR_READ8(mmio_base + 0);

	return num_used_qps;
}

static int
zsda_check_write(uint8_t *addr, const uint32_t dst_value)
{
	int times = ZSDA_TIME_NUM;
	uint32_t val;

	val = ZSDA_CSR_READ32(addr);

	while ((val != dst_value) && times--) {
		val = ZSDA_CSR_READ32(addr);
		rte_delay_us_sleep(ZSDA_TIME_SLEEP_US);
	}
	if (val == dst_value)
		return ZSDA_SUCCESS;
	else
		return ZSDA_FAILED;
}


static int
zsda_admin_q_start(const struct rte_pci_device *pci_dev)
{
	uint8_t *mmio_base = pci_dev->mem_resource[0].addr;
	int ret = 0;

	ZSDA_CSR_WRITE32(mmio_base + ZSDA_ADMIN_Q_START, 0);

	ZSDA_CSR_WRITE32(mmio_base + ZSDA_ADMIN_Q_START, ZSDA_Q_START);
	ret = zsda_check_write(mmio_base + ZSDA_ADMIN_Q_START, ZSDA_Q_START);

	return ret;
}

static int
zsda_admin_q_stop(const struct rte_pci_device *pci_dev)
{
	uint8_t *mmio_base = pci_dev->mem_resource[0].addr;
	int ret = 0;

	ZSDA_CSR_WRITE32(mmio_base + ZSDA_ADMIN_Q_STOP_RESP, ZSDA_RESP_INVALID);
	ZSDA_CSR_WRITE32(mmio_base + ZSDA_ADMIN_Q_STOP, ZSDA_Q_STOP);

	ret = zsda_check_write(mmio_base + ZSDA_ADMIN_Q_STOP_RESP,
			       ZSDA_RESP_VALID);

	if (ret)
		ZSDA_LOG(INFO, "Failed! zsda_admin q stop");

	return ret;
}

static int
zsda_admin_q_clear(const struct rte_pci_device *pci_dev)
{
	uint8_t *mmio_base = pci_dev->mem_resource[0].addr;
	int ret = 0;

	ZSDA_CSR_WRITE32(mmio_base + ZSDA_ADMIN_Q_CLR_RESP, ZSDA_RESP_INVALID);
	ZSDA_CSR_WRITE32(mmio_base + ZSDA_ADMIN_Q_CLR, ZSDA_RESP_VALID);

	ret = zsda_check_write(mmio_base + ZSDA_ADMIN_Q_CLR_RESP,
			       ZSDA_RESP_VALID);

	if (ret)
		ZSDA_LOG(INFO, "Failed! zsda_admin q clear");

	return ret;
}


static int
zsda_queue_start_single(uint8_t *mmio_base, const uint8_t id)
{
	uint8_t *addr_start = mmio_base + ZSDA_IO_Q_START + (4 * id);

	ZSDA_CSR_WRITE32(addr_start, ZSDA_Q_START);
	return zsda_check_write(addr_start, ZSDA_Q_START);
}


static int
zsda_queue_stop_single(uint8_t *mmio_base, const uint8_t id)
{
	int ret = 0;
	uint8_t *addr_stop = mmio_base + ZSDA_IO_Q_STOP + (4 * id);
	uint8_t *addr_resp = mmio_base + ZSDA_IO_Q_STOP_RESP + (4 * id);

	ZSDA_CSR_WRITE32(addr_resp, ZSDA_RESP_INVALID);
	ZSDA_CSR_WRITE32(addr_stop, ZSDA_Q_STOP);

	ret = zsda_check_write(addr_resp, ZSDA_RESP_VALID);
	ZSDA_CSR_WRITE32(addr_resp, ZSDA_RESP_INVALID);

	return ret;
}

static int
zsda_queue_clear_single(uint8_t *mmio_base, const uint8_t id)
{
	int ret = 0;
	uint8_t *addr_clear = mmio_base + ZSDA_IO_Q_CLR + (4 * id);
	uint8_t *addr_resp = mmio_base + ZSDA_IO_Q_CLR_RESP + (4 * id);

	ZSDA_CSR_WRITE32(addr_resp, ZSDA_RESP_INVALID);
	ZSDA_CSR_WRITE32(addr_clear, ZSDA_CLEAR_VALID);
	ret = zsda_check_write(addr_resp, ZSDA_RESP_VALID);
	ZSDA_CSR_WRITE32(addr_clear, ZSDA_CLEAR_INVALID);

	return ret;
}

int
zsda_queue_start(const struct rte_pci_device *pci_dev)
{
	uint8_t *mmio_base = pci_dev->mem_resource[0].addr;
	uint8_t id;
	int ret = 0;

	for (id = 0; id < zsda_num_used_qps; id++)
		ret |= zsda_queue_start_single(mmio_base, id);

	return ret;
}

int
zsda_queue_stop(const struct rte_pci_device *pci_dev)
{
	uint8_t *mmio_base = pci_dev->mem_resource[0].addr;
	uint8_t id;
	int ret = 0;

	for (id = 0; id < zsda_num_used_qps; id++)
		ret |= zsda_queue_stop_single(mmio_base, id);

	return ret;
}

static int
zsda_queue_clear(const struct rte_pci_device *pci_dev)
{
	uint8_t *mmio_base = pci_dev->mem_resource[0].addr;
	uint8_t id;
	int ret = 0;

	for (id = 0; id < zsda_num_used_qps; id++)
		ret |= zsda_queue_clear_single(mmio_base, id);

	return ret;
}

static uint16_t
zsda_qps_per_service(const struct zsda_pci_device *zsda_pci_dev,
		     const enum zsda_service_type service)
{
	uint16_t qp_hw_num = 0;

	if (service < ZSDA_SERVICE_INVALID)
		qp_hw_num = zsda_pci_dev->zsda_qp_hw_num[service];
	return qp_hw_num;
}

struct zsda_num_qps zsda_nb_qps;
static void
zsda_get_nb_qps(const struct zsda_pci_device *zsda_pci_dev)
{
	zsda_nb_qps.encomp =
		zsda_qps_per_service(zsda_pci_dev, ZSDA_SERVICE_COMPRESSION);
	zsda_nb_qps.decomp =
		zsda_qps_per_service(zsda_pci_dev, ZSDA_SERVICE_DECOMPRESSION);
	zsda_nb_qps.encrypt =
		zsda_qps_per_service(zsda_pci_dev, ZSDA_SERVICE_SYMMETRIC_ENCRYPT);
	zsda_nb_qps.decrypt =
		zsda_qps_per_service(zsda_pci_dev, ZSDA_SERVICE_SYMMETRIC_DECRYPT);
	zsda_nb_qps.hash =
		zsda_qps_per_service(zsda_pci_dev, ZSDA_SERVICE_HASH_ENCODE);
}

int
zsda_queue_init(struct zsda_pci_device *zsda_pci_dev)
{
	int ret = 0;

	zsda_num_used_qps = zsda_get_num_used_qps(zsda_pci_dev->pci_dev);
	zsda_num_used_qps++;

	ret = zsda_admin_q_start(zsda_pci_dev->pci_dev);
	if (ret) {
		ZSDA_LOG(ERR, "Failed! admin q start");
		return ret;
	}

	ret = zsda_queue_clear(zsda_pci_dev->pci_dev);
	if (ret) {
		ZSDA_LOG(ERR, "Failed! used zsda_io q clear");
		return ret;
	}

	ret = zsda_get_queue_cfg(zsda_pci_dev);
	if (ret) {
		ZSDA_LOG(ERR, "Failed! zsda_get_queue_cfg");
		return ret;
	}

	zsda_get_nb_qps(zsda_pci_dev);

	return ret;
}


int
zsda_queue_remove(struct zsda_pci_device *zsda_pci_dev)
{
	int ret = 0;

	if (zsda_admin_q_clear(zsda_pci_dev->pci_dev) == ZSDA_FAILED)
		ZSDA_LOG(ERR, "Failed! q clear");

	if (zsda_admin_q_stop(zsda_pci_dev->pci_dev) == ZSDA_FAILED)
		ZSDA_LOG(ERR, "Failed! q stop");

	return ret;
}

struct zsda_qp_hw *
zsda_qps_hw_per_service(struct zsda_pci_device *zsda_pci_dev,
			const enum zsda_service_type service)
{
	struct zsda_qp_hw *qp_hw = NULL;

	if (service < ZSDA_SERVICE_INVALID)
		qp_hw = &(zsda_pci_dev->zsda_hw_qps[service]);

	return qp_hw;
}

static const struct rte_memzone *
zsda_queue_dma_zone_reserve(const char *queue_name, const unsigned int queue_size,
		       const unsigned int socket_id)
{
	const struct rte_memzone *mz;

	mz = rte_memzone_lookup(queue_name);
	if (mz != 0) {
		if (((size_t)queue_size <= mz->len) &&
		    ((socket_id == (SOCKET_ID_ANY & 0xffff)) ||
		     (socket_id == (mz->socket_id & 0xffff)))) {
			ZSDA_LOG(DEBUG,
				 "re-use memzone already allocated for %s",
				 queue_name);
			return mz;
		}
		ZSDA_LOG(ERR, E_MALLOC);
		return NULL;
	}

	mz = rte_memzone_reserve_aligned(queue_name, queue_size,
					   (int)(socket_id & 0xfff),
					   RTE_MEMZONE_IOVA_CONTIG, queue_size);

	return mz;
}

static int
zsda_queue_create(const uint32_t dev_id, struct zsda_queue *queue,
		  const struct zsda_qp_config *qp_conf, const uint8_t dir)
{
	void *io_addr;
	const struct rte_memzone *qp_mz;
	struct qinfo qcfg = {0};

	uint16_t desc_size = ((dir == RING_DIR_TX) ? qp_conf->hw->tx_msg_size
						   : qp_conf->hw->rx_msg_size);
	unsigned int queue_size_bytes = qp_conf->nb_descriptors * desc_size;

	queue->hw_queue_number =
		((dir == RING_DIR_TX) ? qp_conf->hw->tx_ring_num
				      : qp_conf->hw->rx_ring_num);

	struct rte_pci_device *pci_dev = zsda_devs[dev_id].pci_dev;
	struct zsda_pci_device *zsda_dev =
		(struct zsda_pci_device *)zsda_devs[dev_id].mz->addr;

	zsda_get_queue_cfg_by_id(zsda_dev, queue->hw_queue_number, &qcfg);

	if (dir == RING_DIR_TX)
		snprintf(queue->memz_name, sizeof(queue->memz_name),
			 "%s_%d_%s_%s_%d", pci_dev->driver->driver.name, dev_id,
			 qp_conf->service_str, "qptxmem",
			 queue->hw_queue_number);
	else
		snprintf(queue->memz_name, sizeof(queue->memz_name),
			 "%s_%d_%s_%s_%d", pci_dev->driver->driver.name, dev_id,
			 qp_conf->service_str, "qprxmem",
			 queue->hw_queue_number);

	qp_mz = zsda_queue_dma_zone_reserve(queue->memz_name, queue_size_bytes,
				       rte_socket_id());
	if (qp_mz == NULL) {
		ZSDA_LOG(ERR, E_MALLOC);
		return -ENOMEM;
	}

	queue->base_addr = qp_mz->addr;
	queue->base_phys_addr = qp_mz->iova;
	queue->modulo_mask = MAX_NUM_OPS;
	queue->msg_size = desc_size;

	queue->head = (dir == RING_DIR_TX) ? qcfg.wq_head : qcfg.cq_head;
	queue->tail = (dir == RING_DIR_TX) ? qcfg.wq_tail : qcfg.cq_tail;

	if ((queue->head == 0) && (queue->tail == 0))
		qcfg.cycle += 1;

	queue->valid = qcfg.cycle & (ZSDA_MAX_CYCLE - 1);
	queue->queue_size = ZSDA_MAX_DESC;
	queue->cycle_size = ZSDA_MAX_CYCLE;
	queue->io_addr = pci_dev->mem_resource[0].addr;

	memset(queue->base_addr, 0x0, queue_size_bytes);
	io_addr = pci_dev->mem_resource[0].addr;

	if (dir == RING_DIR_TX)
		ZSDA_CSR_WQ_RING_BASE(io_addr, queue->hw_queue_number,
				      queue->base_phys_addr);
	else
		ZSDA_CSR_CQ_RING_BASE(io_addr, queue->hw_queue_number,
				      queue->base_phys_addr);

	return 0;
}

static void
zsda_queue_delete(const struct zsda_queue *queue)
{
	const struct rte_memzone *mz;
	int status;

	if (queue == NULL) {
		ZSDA_LOG(DEBUG, "Invalid queue");
		return;
	}

	mz = rte_memzone_lookup(queue->memz_name);
	if (mz != NULL) {
		memset(queue->base_addr, 0x0,
		       (uint16_t)(queue->queue_size * queue->msg_size));
		status = rte_memzone_free(mz);
		if (status != 0)
			ZSDA_LOG(ERR, E_FREE);
	} else
		ZSDA_LOG(DEBUG, "queue %s doesn't exist", queue->memz_name);
}

void
zsda_stats_reset(void **queue_pairs, const uint32_t nb_queue_pairs)
{
	enum zsda_service_type type;
	uint32_t i;
	struct zsda_qp *qp;

	if (queue_pairs == NULL) {
		ZSDA_LOG(ERR, E_NULL);
		return;
	}

	for (i = 0; i < nb_queue_pairs; i++) {
		qp = queue_pairs[i];

		if (qp == NULL) {
			ZSDA_LOG(ERR, E_NULL);
			break;
		}
		for (type = 0; type < ZSDA_MAX_SERVICES; type++) {
			if (qp->srv[type].used)
				memset(&(qp->srv[type].stats), 0,
				       sizeof(struct zsda_common_stat));
		}
	}
}

void
zsda_stats_get(void **queue_pairs, const uint32_t nb_queue_pairs,
	      struct zsda_common_stat *stats)
{
	enum zsda_service_type type;
	uint32_t i;
	struct zsda_qp *qp;

	if ((stats == NULL) || (queue_pairs == NULL)) {
		ZSDA_LOG(ERR, E_NULL);
		return;
	}

	for (i = 0; i < nb_queue_pairs; i++) {
		qp = queue_pairs[i];

		if (qp == NULL) {
			ZSDA_LOG(ERR, E_NULL);
			break;
		}

		for (type = 0; type < ZSDA_SERVICE_INVALID; type++) {
			if (qp->srv[type].used) {
				stats->enqueued_count +=
					qp->srv[type].stats.enqueued_count;
				stats->dequeued_count +=
					qp->srv[type].stats.dequeued_count;
				stats->enqueue_err_count +=
					qp->srv[type].stats.enqueue_err_count;
				stats->dequeue_err_count +=
					qp->srv[type].stats.dequeue_err_count;
			}
		}
	}
}


static int
zsda_cookie_init(const uint32_t dev_id, struct zsda_qp **qp_addr,
	    const uint16_t queue_pair_id,
	    const struct zsda_qp_config *zsda_qp_conf)
{
	struct zsda_qp *qp = *qp_addr;
	struct rte_pci_device *pci_dev = zsda_devs[dev_id].pci_dev;
	char op_cookie_pool_name[RTE_RING_NAMESIZE];
	uint32_t i;
	enum zsda_service_type type = zsda_qp_conf->service_type;

	if (zsda_qp_conf->nb_descriptors != ZSDA_MAX_DESC)
		ZSDA_LOG(ERR, "Can't create qp for %u descriptors",
			 zsda_qp_conf->nb_descriptors);

	qp->srv[type].nb_descriptors = zsda_qp_conf->nb_descriptors;

	qp->srv[type].op_cookies = rte_zmalloc_socket(
		"zsda PMD op cookie pointer",
		zsda_qp_conf->nb_descriptors *
			sizeof(*qp->srv[type].op_cookies),
		RTE_CACHE_LINE_SIZE, zsda_qp_conf->socket_id);

	if (qp->srv[type].op_cookies == NULL) {
		ZSDA_LOG(ERR, E_MALLOC);
		return -ENOMEM;
	}

	snprintf(op_cookie_pool_name, RTE_RING_NAMESIZE, "%s%d_cks_%s_qp%hu",
		 pci_dev->driver->driver.name, dev_id,
		 zsda_qp_conf->service_str, queue_pair_id);

	qp->srv[type].op_cookie_pool = rte_mempool_lookup(op_cookie_pool_name);
	if (qp->srv[type].op_cookie_pool == NULL)
		qp->srv[type].op_cookie_pool = rte_mempool_create(
			op_cookie_pool_name, qp->srv[type].nb_descriptors,
			zsda_qp_conf->cookie_size, 64, 0, NULL, NULL, NULL,
			NULL, (int)(rte_socket_id() & 0xfff), 0);
	if (!qp->srv[type].op_cookie_pool) {
		ZSDA_LOG(ERR, E_CREATE);
		goto exit;
	}

	for (i = 0; i < qp->srv[type].nb_descriptors; i++) {
		if (rte_mempool_get(qp->srv[type].op_cookie_pool,
				    &qp->srv[type].op_cookies[i])) {
			ZSDA_LOG(ERR, "ZSDA PMD Cannot get op_cookie");
			goto exit;
		}
		memset(qp->srv[type].op_cookies[i], 0,
		       zsda_qp_conf->cookie_size);
	}
	return 0;

exit:
	if (qp->srv[type].op_cookie_pool)
		rte_mempool_free(qp->srv[type].op_cookie_pool);
	rte_free(qp->srv[type].op_cookies);

	return -EFAULT;
}

static int
zsda_queue_pair_setup(const uint32_t dev_id, struct zsda_qp **qp_addr,
		      const uint16_t queue_pair_id,
		      const struct zsda_qp_config *zsda_qp_conf)
{
	struct zsda_qp *qp = *qp_addr;
	struct rte_pci_device *pci_dev = zsda_devs[dev_id].pci_dev;
	int ret = 0;
	enum zsda_service_type type = zsda_qp_conf->service_type;

	if (type >= ZSDA_SERVICE_INVALID) {
		ZSDA_LOG(ERR, "Failed! service type");
		return -EINVAL;
	}

	if (pci_dev->mem_resource[0].addr == NULL) {
		ZSDA_LOG(ERR, E_NULL);
		return -EINVAL;
	}

	if (zsda_queue_create(dev_id, &(qp->srv[type].tx_q), zsda_qp_conf,
			      RING_DIR_TX) != 0) {
		ZSDA_LOG(ERR, E_CREATE);
		return -EFAULT;
	}

	if (zsda_queue_create(dev_id, &(qp->srv[type].rx_q), zsda_qp_conf,
			      RING_DIR_RX) != 0) {
		ZSDA_LOG(ERR, E_CREATE);
		zsda_queue_delete(&(qp->srv[type].tx_q));
		return -EFAULT;
	}

	ret = zsda_cookie_init(dev_id, qp_addr, queue_pair_id, zsda_qp_conf);
	if (ret) {
		zsda_queue_delete(&(qp->srv[type].tx_q));
		zsda_queue_delete(&(qp->srv[type].rx_q));
		qp->srv[type].used = false;
	}
	qp->srv[type].used = true;
	return ret;
}

int
zsda_queue_pair_release(struct zsda_qp **qp_addr)
{
	struct zsda_qp *qp = *qp_addr;
	uint32_t i;
	enum zsda_service_type type;

	if (qp == NULL) {
		ZSDA_LOG(DEBUG, "qp already freed");
		return 0;
	}

	for (type = 0; type < ZSDA_SERVICE_INVALID; type++) {
		if (!qp->srv[type].used)
			continue;

		zsda_queue_delete(&(qp->srv[type].tx_q));
		zsda_queue_delete(&(qp->srv[type].rx_q));
		qp->srv[type].used = false;
		for (i = 0; i < qp->srv[type].nb_descriptors; i++)
			rte_mempool_put(qp->srv[type].op_cookie_pool,
					qp->srv[type].op_cookies[i]);

		if (qp->srv[type].op_cookie_pool)
			rte_mempool_free(qp->srv[type].op_cookie_pool);

		rte_free(qp->srv[type].op_cookies);
	}

	rte_free(qp);
	*qp_addr = NULL;

	return 0;
}

static int
zsda_find_next_free_cookie(const struct zsda_queue *queue, void **op_cookie,
		      uint16_t *idx)
{
	uint16_t old_tail = queue->tail;
	uint16_t tail = queue->tail;
	struct zsda_op_cookie *cookie;

	do {
		cookie = op_cookie[tail];
		if (!cookie->used) {
			*idx = tail & (queue->queue_size - 1);
			return 0;
		}
		tail = zsda_modulo_16(tail++, queue->modulo_mask);
	} while (old_tail != tail);

	return -EINVAL;
}

static int
zsda_enqueue(void *op, struct zsda_qp *qp)
{
	uint16_t new_tail;
	enum zsda_service_type type;
	void **op_cookie;
	int ret = 0;
	struct zsda_queue *queue;

	for (type = 0; type < ZSDA_SERVICE_INVALID; type++) {
		if (qp->srv[type].used) {
			if (!qp->srv[type].match(op))
				continue;
			queue = &qp->srv[type].tx_q;
			op_cookie = qp->srv[type].op_cookies;

			if (zsda_find_next_free_cookie(queue, op_cookie,
						  &new_tail)) {
				ret = -EBUSY;
				break;
			}
			ret = qp->srv[type].tx_cb(op, queue, op_cookie,
						  new_tail);
			if (ret) {
				qp->srv[type].stats.enqueue_err_count++;
				ZSDA_LOG(ERR, "Failed! config wqe");
				break;
			}
			qp->srv[type].stats.enqueued_count++;

			queue->tail = zsda_modulo_16(new_tail + 1,
						     queue->queue_size - 1);

			if (new_tail > queue->tail)
				queue->valid =
					zsda_modulo_8(queue->valid + 1,
					(uint8_t)(queue->cycle_size - 1));

			queue->pushed_wqe++;
			break;
		}
	}

	return ret;
}

static void
zsda_tx_write_tail(struct zsda_queue *queue)
{
	if (queue->pushed_wqe)
		WRITE_CSR_WQ_TAIL(queue->io_addr, queue->hw_queue_number,
				  queue->tail);

	queue->pushed_wqe = 0;
}

uint16_t
zsda_enqueue_op_burst(struct zsda_qp *qp, void **ops, uint16_t nb_ops)
{
	int ret = 0;
	enum zsda_service_type type;
	uint16_t i;
	uint16_t nb_send = 0;
	void *op;

	if (nb_ops > ZSDA_MAX_DESC) {
		ZSDA_LOG(ERR, "Enqueue number bigger than %d", ZSDA_MAX_DESC);
		return 0;
	}

	for (i = 0; i < nb_ops; i++) {
		op = ops[i];
		ret = zsda_enqueue(op, qp);
		if (ret < 0)
			break;
		nb_send++;
	}

	for (type = 0; type < ZSDA_SERVICE_INVALID; type++)
		if (qp->srv[type].used)
			zsda_tx_write_tail(&qp->srv[type].tx_q);

	return nb_send;
}

static void
zsda_dequeue(struct qp_srv *srv, void **ops, const uint16_t nb_ops, uint16_t *nb)
{
	uint16_t head;
	struct zsda_cqe *cqe;
	struct zsda_queue *queue = &srv->rx_q;
	struct zsda_op_cookie *cookie;
	head = queue->head;

	while (*nb < nb_ops) {
		cqe = (struct zsda_cqe *)(
			(uint8_t *)queue->base_addr + head * queue->msg_size);

		if (!CQE_VALID(cqe->err1))
			break;
		cookie = srv->op_cookies[cqe->sid];

		ops[*nb] = cookie->op;
		if (srv->rx_cb(cookie, cqe) == ZSDA_SUCCESS)
			srv->stats.dequeued_count++;
		else {
			ZSDA_LOG(ERR,
				 "ERR! Cqe, opcode 0x%x, sid 0x%x, "
				 "tx_real_length 0x%x, err0 0x%x, err1 0x%x",
				 cqe->op_code, cqe->sid, cqe->tx_real_length,
				 cqe->err0, cqe->err1);
			srv->stats.dequeue_err_count++;
		}
		(*nb)++;
		cookie->used = false;

		head = zsda_modulo_16(head + 1, queue->modulo_mask);
		queue->head = head;
		WRITE_CSR_CQ_HEAD(queue->io_addr, queue->hw_queue_number, head);
		memset(cqe, 0x0, sizeof(struct zsda_cqe));
	}
}

int
zsda_common_setup_qp(uint32_t zsda_dev_id, struct zsda_qp **qp_addr,
		const uint16_t queue_pair_id, const struct zsda_qp_config *conf)
{
	uint32_t i;
	int ret = 0;
	struct zsda_qp *qp;
	rte_iova_t cookie_phys_addr;

	ret = zsda_queue_pair_setup(zsda_dev_id, qp_addr, queue_pair_id, conf);
	if (ret)
		return ret;

	qp = (struct zsda_qp *)*qp_addr;

	for (i = 0; i < qp->srv[conf->service_type].nb_descriptors; i++) {
		struct zsda_op_cookie *cookie =
			qp->srv[conf->service_type].op_cookies[i];
		cookie_phys_addr = rte_mempool_virt2iova(cookie);

		cookie->comp_head_phys_addr = cookie_phys_addr +
			offsetof(struct zsda_op_cookie, comp_head);

		cookie->sgl_src_phys_addr = cookie_phys_addr +
			offsetof(struct zsda_op_cookie, sgl_src);

		cookie->sgl_dst_phys_addr = cookie_phys_addr +
			offsetof(struct zsda_op_cookie, sgl_dst);
	}
	return ret;
}

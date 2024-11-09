/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 ZTE Corporation
 */

#include <stdint.h>
#include <rte_mempool.h>

#include "zsda_logs.h"
#include "zsda_qp.h"
#include "zsda_qp_common.h"

#define MAGIC_SEND 0xab
#define MAGIC_RECV 0xcd
#define ADMIN_VER 1
#define RING_DIR_TX 0
#define RING_DIR_RX 1

static uint8_t zsda_num_used_qps;

static const uint8_t crc8_table[256] = {
	0x00, 0x41, 0x13, 0x52, 0x26, 0x67, 0x35, 0x74, 0x4c, 0x0d, 0x5f, 0x1e,
	0x6a, 0x2b, 0x79, 0x38, 0x09, 0x48, 0x1a, 0x5b, 0x2f, 0x6e, 0x3c, 0x7d,
	0x45, 0x04, 0x56, 0x17, 0x63, 0x22, 0x70, 0x31, 0x12, 0x53, 0x01, 0x40,
	0x34, 0x75, 0x27, 0x66, 0x5e, 0x1f, 0x4d, 0x0c, 0x78, 0x39, 0x6b, 0x2a,
	0x1b, 0x5a, 0x08, 0x49, 0x3d, 0x7c, 0x2e, 0x6f, 0x57, 0x16, 0x44, 0x05,
	0x71, 0x30, 0x62, 0x23, 0x24, 0x65, 0x37, 0x76, 0x02, 0x43, 0x11, 0x50,
	0x68, 0x29, 0x7b, 0x3a, 0x4e, 0x0f, 0x5d, 0x1c, 0x2d, 0x6c, 0x3e, 0x7f,
	0x0b, 0x4a, 0x18, 0x59, 0x61, 0x20, 0x72, 0x33, 0x47, 0x06, 0x54, 0x15,
	0x36, 0x77, 0x25, 0x64, 0x10, 0x51, 0x03, 0x42, 0x7a, 0x3b, 0x69, 0x28,
	0x5c, 0x1d, 0x4f, 0x0e, 0x3f, 0x7e, 0x2c, 0x6d, 0x19, 0x58, 0x0a, 0x4b,
	0x73, 0x32, 0x60, 0x21, 0x55, 0x14, 0x46, 0x07, 0x48, 0x09, 0x5b, 0x1a,
	0x6e, 0x2f, 0x7d, 0x3c, 0x04, 0x45, 0x17, 0x56, 0x22, 0x63, 0x31, 0x70,
	0x41, 0x00, 0x52, 0x13, 0x67, 0x26, 0x74, 0x35, 0x0d, 0x4c, 0x1e, 0x5f,
	0x2b, 0x6a, 0x38, 0x79, 0x5a, 0x1b, 0x49, 0x08, 0x7c, 0x3d, 0x6f, 0x2e,
	0x16, 0x57, 0x05, 0x44, 0x30, 0x71, 0x23, 0x62, 0x53, 0x12, 0x40, 0x01,
	0x75, 0x34, 0x66, 0x27, 0x1f, 0x5e, 0x0c, 0x4d, 0x39, 0x78, 0x2a, 0x6b,
	0x6c, 0x2d, 0x7f, 0x3e, 0x4a, 0x0b, 0x59, 0x18, 0x20, 0x61, 0x33, 0x72,
	0x06, 0x47, 0x15, 0x54, 0x65, 0x24, 0x76, 0x37, 0x43, 0x02, 0x50, 0x11,
	0x29, 0x68, 0x3a, 0x7b, 0x0f, 0x4e, 0x1c, 0x5d, 0x7e, 0x3f, 0x6d, 0x2c,
	0x58, 0x19, 0x4b, 0x0a, 0x32, 0x73, 0x21, 0x60, 0x14, 0x55, 0x07, 0x46,
	0x77, 0x36, 0x64, 0x25, 0x51, 0x10, 0x42, 0x03, 0x3b, 0x7a, 0x28, 0x69,
	0x1d, 0x5c, 0x0e, 0x4f};

static uint8_t
zsda_crc8(const uint8_t *message, const int length)
{
	uint8_t crc = 0;
	int i;

	for (i = 0; i < length; i++)
		crc = crc8_table[crc ^ message[i]];
	return crc;
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
	int ret;

	ZSDA_CSR_WRITE32(mmio_base + ZSDA_ADMIN_Q_START, 0);

	ZSDA_CSR_WRITE32(mmio_base + ZSDA_ADMIN_Q_START, ZSDA_Q_START);
	ret = zsda_check_write(mmio_base + ZSDA_ADMIN_Q_START, ZSDA_Q_START);

	return ret;
}

static int __rte_unused
zsda_admin_q_stop(const struct rte_pci_device *pci_dev)
{
	uint8_t *mmio_base = pci_dev->mem_resource[0].addr;
	int ret;

	ZSDA_CSR_WRITE32(mmio_base + ZSDA_ADMIN_Q_STOP_RESP, ZSDA_RESP_INVALID);
	ZSDA_CSR_WRITE32(mmio_base + ZSDA_ADMIN_Q_STOP, ZSDA_Q_STOP);

	ret = zsda_check_write(mmio_base + ZSDA_ADMIN_Q_STOP_RESP,
			       ZSDA_RESP_VALID);

	if (ret)
		ZSDA_LOG(INFO, "Failed! zsda_admin q stop");

	return ret;
}

static int __rte_unused
zsda_admin_q_clear(const struct rte_pci_device *pci_dev)
{
	uint8_t *mmio_base = pci_dev->mem_resource[0].addr;
	int ret;

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
	int ret;
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
	int ret;
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
	int ret = ZSDA_SUCCESS;

	for (id = 0; id < zsda_num_used_qps; id++)
		ret |= zsda_queue_start_single(mmio_base, id);

	return ret;
}

int
zsda_queue_stop(const struct rte_pci_device *pci_dev)
{
	uint8_t *mmio_base = pci_dev->mem_resource[0].addr;
	uint8_t id;
	int ret = ZSDA_SUCCESS;

	for (id = 0; id < zsda_num_used_qps; id++)
		ret |= zsda_queue_stop_single(mmio_base, id);

	return ret;
}

static int
zsda_queue_clear(const struct rte_pci_device *pci_dev)
{
	uint8_t *mmio_base = pci_dev->mem_resource[0].addr;
	uint8_t id;
	int ret = ZSDA_SUCCESS;

	for (id = 0; id < zsda_num_used_qps; id++)
		ret |= zsda_queue_clear_single(mmio_base, id);

	return ret;
}

static uint32_t
zsda_set_reg_8(void *addr, const uint8_t val0, const uint8_t val1,
	  const uint8_t val2, const uint8_t val3)
{
	uint8_t val[4];

	val[0] = val0;
	val[1] = val1;
	val[2] = val2;
	val[3] = val3;
	ZSDA_CSR_WRITE32(addr, *(uint32_t *)val);
	return *(uint32_t *)val;
}

static uint8_t
zsda_get_reg_8(void *addr, const int offset)
{
	uint32_t val = ZSDA_CSR_READ32(addr);

	return *(((uint8_t *)&val) + offset);
}

static inline uint32_t
zsda_modulo_32(uint32_t data, uint32_t modulo_mask)
{
	return (data) & (modulo_mask);
}
static inline uint16_t
zsda_modulo_16(uint16_t data, uint16_t modulo_mask)
{
	return (data) & (modulo_mask);
}
static inline uint8_t
zsda_modulo_8(uint8_t data, uint8_t modulo_mask)
{
	return (data) & (modulo_mask);
}

static int
zsda_send_admin_msg(const struct rte_pci_device *pci_dev, void *req,
		    const uint32_t len)
{
	uint8_t *mmio_base = pci_dev->mem_resource[0].addr;
	uint8_t wq_flag;
	uint8_t crc;
	uint16_t admin_db;
	uint32_t retry = ZSDA_TIME_NUM;
	int i;
	uint16_t db;
	int repeat = sizeof(struct zsda_admin_req) / sizeof(uint32_t);

	if (len > ADMIN_BUF_DATA_LEN)
		return -EINVAL;

	for (i = 0; i < repeat; i++) {
		ZSDA_CSR_WRITE32(((uint32_t *)(mmio_base + ZSDA_ADMIN_WQ) + i),
				 *((uint32_t *)req + i));
	}

	crc = zsda_crc8((uint8_t *)req, ADMIN_BUF_DATA_LEN);
	zsda_set_reg_8(mmio_base + ZSDA_ADMIN_WQ_BASE7, crc, ADMIN_VER, MAGIC_SEND, 0);
	rte_delay_us_sleep(ZSDA_TIME_SLEEP_US);
	rte_wmb();

	admin_db = ZSDA_CSR_READ32(mmio_base + ZSDA_ADMIN_WQ_TAIL);
	db = zsda_modulo_32(admin_db, 0x1ff);
	ZSDA_CSR_WRITE32(mmio_base + ZSDA_ADMIN_WQ_TAIL, db);

	do {
		rte_delay_us_sleep(ZSDA_TIME_SLEEP_US);
		wq_flag = zsda_get_reg_8(mmio_base + ZSDA_ADMIN_WQ_BASE7, 2);
		if (wq_flag == MAGIC_RECV)
			break;

		retry--;
		if (!retry) {
			ZSDA_LOG(ERR, "wq_flag 0x%X", wq_flag);
			zsda_set_reg_8(mmio_base + ZSDA_ADMIN_WQ_BASE7, 0, crc,
				  ADMIN_VER, 0);
			return -EIO;
		}
	} while (1);

	return ZSDA_SUCCESS;
}

static int
zsda_recv_admin_msg(const struct rte_pci_device *pci_dev, void *resp,
		    const uint32_t len)
{
	uint8_t *mmio_base = pci_dev->mem_resource[0].addr;
	uint8_t cq_flag;
	uint32_t retry = ZSDA_TIME_NUM;
	uint8_t crc;
	uint8_t buf[ADMIN_BUF_TOTAL_LEN] = {0};
	uint32_t i;

	if (len > ADMIN_BUF_DATA_LEN)
		return -EINVAL;

	do {
		rte_delay_us_sleep(ZSDA_TIME_SLEEP_US);

		cq_flag = zsda_get_reg_8(mmio_base + ZSDA_ADMIN_CQ_BASE7, 2);
		if (cq_flag == MAGIC_SEND)
			break;

		retry--;
		if (!retry)
			return -EIO;
	} while (1);

	for (i = 0; i < len; i++)
		buf[i] = ZSDA_CSR_READ8(mmio_base + ZSDA_ADMIN_CQ + i);

	crc = ZSDA_CSR_READ8(mmio_base + ZSDA_ADMIN_CQ_CRC);
	rte_rmb();
	ZSDA_CSR_WRITE8(mmio_base + ZSDA_ADMIN_CQ_FLAG, MAGIC_RECV);
	if (crc != zsda_crc8(buf, ADMIN_BUF_DATA_LEN)) {
		ZSDA_LOG(ERR, "[%d] Failed! crc error!", __LINE__);
		return -EIO;
	}

	memcpy(resp, buf, len);

	return ZSDA_SUCCESS;
}

static int
zsda_admin_msg_init(const struct rte_pci_device *pci_dev)
{
	uint8_t *mmio_base = pci_dev->mem_resource[0].addr;

	zsda_set_reg_8(mmio_base + ZSDA_ADMIN_WQ_BASE7, 0, 0, MAGIC_RECV, 0);
	zsda_set_reg_8(mmio_base + ZSDA_ADMIN_CQ_BASE7, 0, 0, MAGIC_RECV, 0);
	return 0;
}

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
	int ret;
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

	*qcfg = resp.qcfg;

	return ZSDA_SUCCESS;
}

static struct ring_size zsda_qp_hw_ring_size[ZSDA_MAX_SERVICES] = {
	[ZSDA_SERVICE_ENCOMPRESSION] = {32, 16},
	[ZSDA_SERVICE_DECOMPRESSION] = {32, 16},
};

static int
zsda_get_queue_cfg(struct zsda_pci_device *zsda_pci_dev)
{
	uint8_t i;
	uint32_t index;
	enum zsda_service_type type;
	struct zsda_qp_hw *zsda_hw_qps = zsda_pci_dev->zsda_hw_qps;
	struct qinfo qcfg = {0};
	int ret;

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

static int
zsda_unmask_flr(const struct zsda_pci_device *zsda_pci_dev)
{
	struct zsda_admin_req_qcfg req = {0};
	struct zsda_admin_resp_qcfg resp = {0};

	int ret = 0;
	struct rte_pci_device *pci_dev =
		zsda_devs[zsda_pci_dev->zsda_dev_id].pci_dev;

	zsda_admin_msg_init(pci_dev);

	req.msg_type = ZSDA_FLR_SET_FUNCTION;

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

	return ZSDA_SUCCESS;
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
		zsda_qps_per_service(zsda_pci_dev, ZSDA_SERVICE_ENCOMPRESSION);
	zsda_nb_qps.decomp =
		zsda_qps_per_service(zsda_pci_dev, ZSDA_SERVICE_DECOMPRESSION);
}

int
zsda_queue_init(struct zsda_pci_device *zsda_pci_dev)
{
	int ret;

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

	ret = zsda_unmask_flr(zsda_pci_dev);
	if (ret) {
		ZSDA_LOG(ERR, "Failed! zsda_unmask_flr");
		return ret;
	}

	zsda_get_nb_qps(zsda_pci_dev);

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
zsda_queue_dma_zone_reserve(const char *queue_name,
				const unsigned int queue_size,
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
		ZSDA_LOG(ERR, "Failed! queue_name exist");
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
		ZSDA_LOG(ERR, "Failed! qp_mz is NULL");
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
		ZSDA_LOG(ERR, "Failed! op_cookies is NULL");
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
		ZSDA_LOG(ERR, "Failed! op_cookie_pool is NULL");
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
	return ZSDA_SUCCESS;

exit:

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
	int ret;
	enum zsda_service_type type = zsda_qp_conf->service_type;

	if (type >= ZSDA_SERVICE_INVALID) {
		ZSDA_LOG(ERR, "Failed! service type");
		return -EINVAL;
	}

	if (pci_dev->mem_resource[0].addr == NULL) {
		ZSDA_LOG(ERR, "Failed! mem_resource[0].addr is NULL");
		return -EINVAL;
	}

	if (zsda_queue_create(dev_id, &(qp->srv[type].tx_q), zsda_qp_conf,
			      RING_DIR_TX) != 0) {
		ZSDA_LOG(ERR, "Failed! zsda_queue_create tx");
		return -EFAULT;
	}

	if (zsda_queue_create(dev_id, &(qp->srv[type].rx_q), zsda_qp_conf,
			      RING_DIR_RX) != 0) {
		ZSDA_LOG(ERR, "Failed! zsda_queue_create rx");
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
zsda_common_setup_qp(uint32_t zsda_dev_id, struct zsda_qp **qp_addr,
		const uint16_t queue_pair_id, const struct zsda_qp_config *conf)
{
	uint32_t i;
	int ret;
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

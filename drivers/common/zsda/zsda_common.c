/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 ZTE Corporation
 */

#include "zsda_common.h"
#include "zsda_logs.h"

#include "bus_pci_driver.h"

#define MAGIC_SEND 0xab
#define MAGIC_RECV 0xcd
#define ADMIN_VER 1

static uint8_t crc8_table[256] = {
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
zsda_crc8(uint8_t *message, int length)
{
	uint8_t crc = 0;
	int i;

	for (i = 0; i < length; i++)
		crc = crc8_table[crc ^ message[i]];
	return crc;
}

uint32_t
set_reg_8(void *addr, uint8_t val0, uint8_t val1, uint8_t val2, uint8_t val3)
{
	uint8_t val[4];
	val[0] = val0;
	val[1] = val1;
	val[2] = val2;
	val[3] = val3;
	ZSDA_CSR_WRITE32(addr, *(uint32_t *)val);
	return *(uint32_t *)val;
}

uint8_t
get_reg_8(void *addr, int offset)
{
	uint32_t val = ZSDA_CSR_READ32(addr);

	return *(((uint8_t *)&val) + offset);
}

int
zsda_admin_msg_init(struct rte_pci_device *pci_dev)
{
	uint8_t *mmio_base = pci_dev->mem_resource[0].addr;

	set_reg_8(mmio_base + ZSDA_ADMIN_WQ_BASE7, 0, 0, MAGIC_RECV, 0);
	set_reg_8(mmio_base + ZSDA_ADMIN_CQ_BASE7, 0, 0, MAGIC_RECV, 0);
	return 0;
}

int
zsda_send_admin_msg(struct rte_pci_device *pci_dev, void *req, uint32_t len)
{
	uint8_t *mmio_base = pci_dev->mem_resource[0].addr;
	uint8_t wq_flag = 0;
	uint8_t crc = 0;
	uint16_t admin_db = 0;
	uint32_t retry = ZSDA_TIME_NUM;
	int i = 0;
	uint16_t db = 0;
	int repeat = sizeof(struct zsda_admin_req) / sizeof(uint32_t);

	if (len > ADMIN_BUF_DATA_LEN)
		return -EINVAL;

	for (i = 0; i < repeat; i++) {
		ZSDA_CSR_WRITE32(((uint32_t *)(mmio_base + ZSDA_ADMIN_WQ) + i),
				 *((uint32_t *)req + i));
	}

	crc = zsda_crc8((uint8_t *)req, ADMIN_BUF_DATA_LEN);
	set_reg_8(mmio_base + ZSDA_ADMIN_WQ_BASE7, crc, ADMIN_VER, MAGIC_SEND, 0);
	rte_delay_us_sleep(ZSDA_TIME_SLEEP_US);
	rte_wmb();

	admin_db = ZSDA_CSR_READ32(mmio_base + ZSDA_ADMIN_WQ_TAIL);
	db = zsda_modulo_32(admin_db, 0x1ff);
	ZSDA_CSR_WRITE32(mmio_base + ZSDA_ADMIN_WQ_TAIL, db);

	do {
		rte_delay_us_sleep(ZSDA_TIME_SLEEP_US);
		wq_flag = get_reg_8(mmio_base + ZSDA_ADMIN_WQ_BASE7, 2);
		if (wq_flag == MAGIC_RECV)
			break;

		retry--;
		if (!retry) {
			ZSDA_LOG(ERR, "wq_flag 0x%X\n", wq_flag);
			set_reg_8(mmio_base + ZSDA_ADMIN_WQ_BASE7, 0, crc,
				  ADMIN_VER, 0);
			return -EIO;
		}
	} while (1);

	return ZSDA_SUCCESS;
}

int
zsda_recv_admin_msg(struct rte_pci_device *pci_dev, void *resp, uint32_t len)
{
	uint8_t *mmio_base = pci_dev->mem_resource[0].addr;
	uint8_t cq_flag = 0;
	uint32_t retry = ZSDA_TIME_NUM;
	uint8_t crc = 0;
	uint8_t buf[ADMIN_BUF_TOTAL_LEN] = {0};
	uint32_t i = 0;

	if (len > ADMIN_BUF_DATA_LEN)
		return -EINVAL;

	do {
		rte_delay_us_sleep(ZSDA_TIME_SLEEP_US);

		cq_flag = get_reg_8(mmio_base + ZSDA_ADMIN_CQ_BASE7, 2);
		if (cq_flag == MAGIC_SEND)
			break;

		retry--;
		if (!retry)
			return -EIO;
	} while (1);

	for (i = 0; i < len; i++)
		buf[i] = ZSDA_CSR_READ8(
			(uint8_t *)(mmio_base + ZSDA_ADMIN_CQ + i));

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

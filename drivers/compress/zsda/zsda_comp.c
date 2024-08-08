/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 ZTE Corporation
 */

#include <rte_bus_pci.h>
#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_comp.h>
#include <rte_hexdump.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_mempool.h>
#include <rte_memzone.h>
#include <rte_spinlock.h>

#include "zsda_comp.h"
#include "zsda_logs.h"

#include <zlib.h>

#define ZLIB_HEADER_SIZE 2
#define ZLIB_TRAILER_SIZE 4
#define GZIP_HEADER_SIZE 10
#define GZIP_TRAILER_SIZE 8
#define CHECKSUM_SIZE 4

static uint32_t zsda_read_chksum(uint8_t *data_addr, uint8_t op_code,
					 uint32_t produced);

int
comp_match(void *op_in)
{
	const struct rte_comp_op *op = (struct rte_comp_op *)op_in;
	const struct zsda_comp_xform *xform =
		(struct zsda_comp_xform *)op->private_xform;

	if (op->op_type != RTE_COMP_OP_STATELESS)
		return 0;

	if (xform->type != RTE_COMP_COMPRESS)
		return 0;

	return 1;
}

static uint8_t
get_opcode(const struct zsda_comp_xform *xform)
{
	if (xform->type == RTE_COMP_COMPRESS) {
		if (xform->checksum_type == RTE_COMP_CHECKSUM_NONE ||
		    xform->checksum_type == RTE_COMP_CHECKSUM_CRC32)
			return ZSDA_OPC_COMP_GZIP;
		else if (xform->checksum_type == RTE_COMP_CHECKSUM_ADLER32)
			return ZSDA_OPC_COMP_ZLIB;
	}
	if (xform->type == RTE_COMP_DECOMPRESS) {
		if (xform->checksum_type == RTE_COMP_CHECKSUM_CRC32 ||
		    xform->checksum_type == RTE_COMP_CHECKSUM_NONE)
			return ZSDA_OPC_DECOMP_GZIP;
		else if (xform->checksum_type == RTE_COMP_CHECKSUM_ADLER32)
			return ZSDA_OPC_DECOMP_ZLIB;
	}

	return ZSDA_OPC_INVALID;
}

int
build_comp_request(void *op_in, const struct zsda_queue *queue,
		   void **op_cookies, uint16_t new_tail)
{
	uint8_t opcode = ZSDA_OPC_INVALID;
	struct rte_comp_op *op = op_in;
	struct zsda_comp_xform *xform =
		(struct zsda_comp_xform *)op->private_xform;
	struct zsda_wqe_comp *wqe =
		(struct zsda_wqe_comp *)(queue->base_addr +
					 (new_tail * queue->msg_size));

	struct zsda_op_cookie *cookie =
		(struct zsda_op_cookie *)op_cookies[new_tail];
	int ret = 0;
	uint32_t op_offset = 0;
	uint32_t op_src_len = 0;
	uint32_t op_dst_len = 0;
	struct zsda_sgl *sgl_src = (struct zsda_sgl *)&cookie->sgl_src;
	struct zsda_sgl *sgl_dst = (struct zsda_sgl *)&cookie->sgl_dst;
	uint32_t head_len = 0;

	if ((op->m_dst == NULL) || (op->m_dst == op->m_src)) {
		ZSDA_LOG(ERR, "Failed! m_dst");
		return -EINVAL;
	}

	opcode = get_opcode(xform);
	if (opcode == ZSDA_OPC_INVALID) {
		ZSDA_LOG(ERR, E_CONFIG);
		return -EINVAL;
	}

	cookie->used = true;
	cookie->sid = new_tail;
	cookie->op = op;

	if (opcode == ZSDA_OPC_COMP_GZIP)
		head_len = GZIP_HEADER_SIZE;
	else if (opcode == ZSDA_OPC_COMP_ZLIB)
		head_len = ZLIB_HEADER_SIZE;
	else {
		ZSDA_LOG(ERR, "Comp, op_code error!");
		return -EINVAL;
	}
	op_src_len += head_len;

	struct comp_head_info comp_head_info;
	comp_head_info.head_len = head_len;
	comp_head_info.head_phys_addr = cookie->comp_head_phys_addr;

	op_offset = op->src.offset;
	op_src_len = op->src.length;
	ret = zsda_fill_sgl(op->m_src, op_offset, sgl_src,
				   cookie->sgl_src_phys_addr, op_src_len, NULL);

	op_offset = op->dst.offset;
	op_dst_len = op->m_dst->pkt_len - op_offset;
	op_dst_len += head_len;
	ret = zsda_fill_sgl(op->m_dst, op_offset, sgl_dst,
					cookie->sgl_dst_phys_addr, op_dst_len,
					&comp_head_info);

	if (ret) {
		ZSDA_LOG(ERR, E_FUNC);
		return ret;
	}

	memset(wqe, 0, sizeof(struct zsda_wqe_comp));
	wqe->rx_length = op_src_len;
	wqe->tx_length = op_dst_len;
	wqe->valid = queue->valid;
	wqe->op_code = opcode;
	wqe->sid = cookie->sid;
	wqe->rx_sgl_type = SGL_ELM_TYPE_LIST;
	wqe->tx_sgl_type = SGL_ELM_TYPE_LIST;

	wqe->rx_addr = cookie->sgl_src_phys_addr;
	wqe->tx_addr = cookie->sgl_dst_phys_addr;

	return ret;
}

int
decomp_match(void *op_in)
{
	const struct rte_comp_op *op = (struct rte_comp_op *)op_in;
	const struct zsda_comp_xform *xform =
		(struct zsda_comp_xform *)op->private_xform;

	if (op->op_type != RTE_COMP_OP_STATELESS)
		return 0;

	if (xform->type != RTE_COMP_DECOMPRESS)
		return 0;
	return 1;
}

int
build_decomp_request(void *op_in, const struct zsda_queue *queue,
		     void **op_cookies, uint16_t new_tail)
{
	uint8_t opcode = ZSDA_OPC_INVALID;
	struct rte_comp_op *op = op_in;
	struct zsda_comp_xform *xform =
		(struct zsda_comp_xform *)op->private_xform;

	struct zsda_wqe_comp *wqe =
		(struct zsda_wqe_comp *)(queue->base_addr +
					 (new_tail * queue->msg_size));
	struct zsda_op_cookie *cookie =
		(struct zsda_op_cookie *)op_cookies[new_tail];
	struct zsda_sgl *sgl_src = (struct zsda_sgl *)&cookie->sgl_src;
	struct zsda_sgl *sgl_dst = (struct zsda_sgl *)&cookie->sgl_dst;
	int ret = 0;

	uint32_t op_offset = 0;
	uint32_t op_src_len = 0;
	uint32_t op_dst_len = 0;

	uint8_t *head_data = NULL;
	uint16_t head_len = 0;
	struct comp_head_info comp_head_info;
	uint8_t head_zlib[ZLIB_HEADER_SIZE] = {0x78, 0xDA};
	uint8_t head_gzip[GZIP_HEADER_SIZE] = {0x1F, 0x8B, 0x08, 0x00, 0x00,
					       0x00, 0x00, 0x00, 0x00, 0x03};

	if ((op->m_dst == NULL) || (op->m_dst == op->m_src)) {
		ZSDA_LOG(ERR, "Failed! m_dst");
		return -EINVAL;
	}

	opcode = get_opcode(xform);
	if (opcode == ZSDA_OPC_INVALID) {
		ZSDA_LOG(ERR, E_CONFIG);
		return -EINVAL;
	}

	cookie->used = true;
	cookie->sid = new_tail;
	cookie->op = op;

	if (opcode == ZSDA_OPC_DECOMP_GZIP) {
		head_data = head_gzip;
		head_len = GZIP_HEADER_SIZE;
	} else if (opcode == ZSDA_OPC_DECOMP_ZLIB) {
		head_data = head_zlib;
		head_len = ZLIB_HEADER_SIZE;
	} else {
		ZSDA_LOG(ERR, "Comp, op_code error!");
		return -EINVAL;
	}

	op_offset = op->src.offset;
	op_src_len = op->src.length;
	op_src_len += head_len;
	comp_head_info.head_len = head_len;
	comp_head_info.head_phys_addr = cookie->comp_head_phys_addr;
	cookie->decomp_no_tail = true;
	for (int i = 0; i < head_len; i++)
		cookie->comp_head[i] = head_data[i];

	ret = zsda_fill_sgl(op->m_src, op_offset, sgl_src,
			    cookie->sgl_src_phys_addr, op_src_len,
			    &comp_head_info);

	op_offset = op->dst.offset;
	op_dst_len = op->m_dst->pkt_len - op_offset;
	ret |= zsda_fill_sgl(op->m_dst, op_offset, sgl_dst,
			     cookie->sgl_dst_phys_addr, op_dst_len, NULL);

	if (ret) {
		ZSDA_LOG(ERR, E_FUNC);
		return ret;
	}

	memset(wqe, 0, sizeof(struct zsda_wqe_comp));

	wqe->rx_length = op_src_len;
	wqe->tx_length = op_dst_len;
	wqe->valid = queue->valid;
	wqe->op_code = opcode;
	wqe->sid = cookie->sid;
	wqe->rx_sgl_type = SGL_ELM_TYPE_LIST;
	wqe->tx_sgl_type = SGL_ELM_TYPE_LIST;
	wqe->rx_addr = cookie->sgl_src_phys_addr;
	wqe->tx_addr = cookie->sgl_dst_phys_addr;

	return ret;
}

void
comp_callbak(void *cookie_in, struct zsda_cqe *cqe)
{
	struct zsda_op_cookie *tmp_cookie = (struct zsda_op_cookie *)cookie_in;
	struct rte_comp_op *tmp_op = (struct rte_comp_op *)tmp_cookie->op;
	uint8_t *data_addr =
		(uint8_t *)tmp_op->m_dst->buf_addr + tmp_op->m_dst->data_off;
	uint32_t chksum = 0;
	uint16_t head_len = 0;
	uint16_t tail_len = 0;

	if (!(CQE_ERR0(cqe->err0) || CQE_ERR1(cqe->err1)))
		tmp_op->status = RTE_COMP_OP_STATUS_SUCCESS;
	else {
		tmp_op->status = RTE_COMP_OP_STATUS_ERROR;
		return;
	}

	/* handle chksum */
	tmp_op->produced = cqe->tx_real_length;
	if (cqe->op_code == ZSDA_OPC_COMP_ZLIB) {
		head_len = ZLIB_HEADER_SIZE;
		tail_len = ZLIB_TRAILER_SIZE;
		chksum = zsda_read_chksum(data_addr, cqe->op_code,
						  tmp_op->produced - head_len);
	}
	if (cqe->op_code == ZSDA_OPC_COMP_GZIP) {
		head_len = GZIP_HEADER_SIZE;
		tail_len = GZIP_TRAILER_SIZE;
		chksum = zsda_read_chksum(data_addr, cqe->op_code,
						  tmp_op->produced - head_len);
	} else if (cqe->op_code == ZSDA_OPC_DECOMP_ZLIB) {
		head_len = ZLIB_HEADER_SIZE;
		tail_len = ZLIB_TRAILER_SIZE;
		chksum = adler32(0, Z_NULL, 0);
		chksum = adler32(chksum, data_addr, tmp_op->produced);
	} else if (cqe->op_code == ZSDA_OPC_DECOMP_GZIP) {
		head_len = GZIP_HEADER_SIZE;
		tail_len = GZIP_TRAILER_SIZE;
		chksum = crc32(0, Z_NULL, 0);
		chksum = crc32(chksum, data_addr, tmp_op->produced);
	}
	tmp_op->output_chksum = chksum;

	if (cqe->op_code == ZSDA_OPC_COMP_ZLIB ||
	    cqe->op_code == ZSDA_OPC_COMP_GZIP) {
		/* remove tail data*/
		rte_pktmbuf_trim(tmp_op->m_dst, GZIP_TRAILER_SIZE);
		/* remove head and tail length */
		tmp_op->produced = tmp_op->produced - (head_len + tail_len);
	}

}

static uint32_t
zsda_read_chksum(uint8_t *data_addr, uint8_t op_code, uint32_t produced)
{
	uint8_t *chk_addr;
	uint32_t chksum = 0;
	int i = 0;

	if (op_code == ZSDA_OPC_COMP_ZLIB) {
		chk_addr = data_addr + produced - ZLIB_TRAILER_SIZE;
		for (i = 0; i < CHECKSUM_SIZE; i++) {
			chksum = chksum << 8;
			chksum |= (*(chk_addr + i));
		}
	} else if (op_code == ZSDA_OPC_COMP_GZIP) {
		chk_addr = data_addr + produced - GZIP_TRAILER_SIZE;
		for (i = 0; i < CHECKSUM_SIZE; i++)
			chksum |= (*(chk_addr + i) << (i * 8));
	}

	return chksum;
}

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2016-2021 Atomic Rules LLC
 */

#include <rte_bbdev.h>
#include <rte_bbdev_pmd.h>

#include <rte_mbuf.h>
#include <rte_hexdump.h>	/* For debug */


#include "ark_bbdev_common.h"
#include "ark_bbdev_custom.h"

/* It is expected that functions in this file will be modified based on
 * specifics of the FPGA hardware beyond the core Arkville
 * components.
 */

/* bytyes must be range of 0 to 20 */
static inline
uint8_t ark_bb_cvt_bytes_meta_cnt(size_t bytes)
{
	return (bytes + 3) / 8;
}

void
ark_bbdev_info_get(struct rte_bbdev *dev,
		   struct rte_bbdev_driver_info *dev_info)
{
	struct ark_bbdevice *ark_bb =  dev->data->dev_private;

	static const struct rte_bbdev_op_cap bbdev_capabilities[] = {
		{
			.type = RTE_BBDEV_OP_LDPC_DEC,
			.cap.ldpc_dec = {
				.capability_flags =
					RTE_BBDEV_LDPC_CRC_24B_ATTACH |
					RTE_BBDEV_LDPC_RATE_MATCH,
				.num_buffers_src =
					RTE_BBDEV_LDPC_MAX_CODE_BLOCKS,
				.num_buffers_hard_out =
					RTE_BBDEV_LDPC_MAX_CODE_BLOCKS
			}
		},
		{
			.type = RTE_BBDEV_OP_LDPC_ENC,
			.cap.ldpc_enc = {
				.capability_flags =
					RTE_BBDEV_LDPC_CRC_24B_ATTACH |
					RTE_BBDEV_LDPC_RATE_MATCH,
				.num_buffers_src =
					RTE_BBDEV_LDPC_MAX_CODE_BLOCKS,
				.num_buffers_dst =
					RTE_BBDEV_LDPC_MAX_CODE_BLOCKS
			}
		},
		RTE_BBDEV_END_OF_CAPABILITIES_LIST(),
	};

	static struct rte_bbdev_queue_conf default_queue_conf = {
		.queue_size = RTE_BBDEV_QUEUE_SIZE_LIMIT,
	};

	default_queue_conf.socket = dev->data->socket_id;

	dev_info->driver_name = RTE_STR(DRIVER_NAME);
	dev_info->max_num_queues = ark_bb->max_nb_queues;
	dev_info->queue_size_lim = RTE_BBDEV_QUEUE_SIZE_LIMIT;
	dev_info->hardware_accelerated = true;
	dev_info->max_dl_queue_priority = 0;
	dev_info->max_ul_queue_priority = 0;
	dev_info->default_queue_conf = default_queue_conf;
	dev_info->capabilities = bbdev_capabilities;
	dev_info->cpu_flag_reqs = NULL;
	dev_info->min_alignment = 4;

}

/* Structure defining layout of the ldpc command struct */
struct ark_bb_ldpc_enc_meta {
	uint16_t header;
	uint8_t rv_index:2,
		basegraph:1,
		code_block_mode:1,
		rfu_71_68:4;

	uint8_t q_m;
	uint32_t e_ea;
	uint32_t eb;
	uint8_t c;
	uint8_t cab;
	uint16_t n_cb;
	uint16_t pad;
	uint16_t trailer;
} __rte_packed;

/* The size must be less then 20 Bytes */
static_assert(sizeof(struct ark_bb_ldpc_enc_meta) <= 20, "struct size");

/* Custom operation on equeue ldpc operation  */
/* Do these function need queue number? */
/* Maximum of 20 bytes */
int
ark_bb_user_enqueue_ldpc_enc(struct rte_bbdev_enc_op *enc_op,
			  uint32_t *meta, uint8_t *meta_cnt)
{
	struct rte_bbdev_op_ldpc_enc *ldpc_enc_op = &enc_op->ldpc_enc;
	struct ark_bb_ldpc_enc_meta *src = (struct ark_bb_ldpc_enc_meta *)meta;

	src->header = 0x4321;	/* For testings */
	src->trailer = 0xFEDC;

	src->rv_index = ldpc_enc_op->rv_index;
	src->basegraph = ldpc_enc_op->basegraph;
	src->code_block_mode = ldpc_enc_op->code_block_mode;

	src->q_m = ldpc_enc_op->q_m;
	src->e_ea = 0xABCD;
	src->eb = ldpc_enc_op->tb_params.eb;
	src->c = ldpc_enc_op->tb_params.c;
	src->cab = ldpc_enc_op->tb_params.cab;

	src->n_cb = 0;

	meta[0] = 0x11111110;
	meta[1] = 0x22222220;
	meta[2] = 0x33333330;
	meta[3] = 0x44444440;
	meta[4] = 0x55555550;

	*meta_cnt = ark_bb_cvt_bytes_meta_cnt(
			sizeof(struct ark_bb_ldpc_enc_meta));
	return 0;
}

/* Custom operation on dequeue ldpc operation  */
int
ark_bb_user_dequeue_ldpc_enc(struct rte_bbdev_enc_op *enc_op,
			     const uint32_t *usermeta)
{
	static int dump;	/* = 0 */
	/* Just compare with what was sent? */
	uint32_t meta_in[5] = {0};
	uint8_t  meta_cnt;

	ark_bb_user_enqueue_ldpc_enc(enc_op, meta_in, &meta_cnt);
	if (memcmp(usermeta, meta_in, 3 + (meta_cnt * 8))) {
		fprintf(stderr,
			"------------------------------------------\n");
		rte_hexdump(stdout, "meta difference for lpdc_enc IN",
			    meta_in, 20);
		rte_hexdump(stdout, "meta difference for lpdc_enc OUT",
			    usermeta, 20);
	} else if (dump) {
		rte_hexdump(stdout, "DUMP lpdc_enc IN", usermeta, 20);
		dump--;
	}

	return 0;
}


/* Turbo op call backs for user meta data */
int ark_bb_user_enqueue_ldpc_dec(struct rte_bbdev_dec_op *enc_op,
				 uint32_t *meta, uint8_t *meta_cnt)
{
	RTE_SET_USED(enc_op);
	meta[0] = 0xF1111110;
	meta[1] = 0xF2222220;
	meta[2] = 0xF3333330;
	meta[3] = 0xF4444440;
	meta[4] = 0xF5555550;

	*meta_cnt = ark_bb_cvt_bytes_meta_cnt(20);
	return 0;
}

int ark_bb_user_dequeue_ldpc_dec(struct rte_bbdev_dec_op *enc_op,
				 const uint32_t *usermeta)
{
	RTE_SET_USED(enc_op);
	static int dump;	/* = 0 */
	/* Just compare with what was sent? */
	uint32_t meta_in[5] = {0};
	uint8_t  meta_cnt;

	ark_bb_user_enqueue_ldpc_dec(enc_op, meta_in, &meta_cnt);
	if (memcmp(usermeta, meta_in, 3 + (meta_cnt * 8))) {
		fprintf(stderr,
			"------------------------------------------\n");
		rte_hexdump(stdout, "meta difference for lpdc_enc IN",
			    meta_in, 20);
		rte_hexdump(stdout, "meta difference for lpdc_enc OUT",
			    usermeta, 20);
	} else if (dump) {
		rte_hexdump(stdout, "DUMP lpdc_enc IN", usermeta, 20);
		dump--;
	}
	return 0;
}

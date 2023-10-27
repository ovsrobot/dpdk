/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Marvell International Ltd.
 */

#ifndef _NITROX_COMP_REQMGR_H_
#define _NITROX_COMP_REQMGR_H_

#define NITROX_DECOMP_CTX_SIZE 2048
#define NITROX_CONSTANTS_MAX_SEARCH_DEPTH 31744

struct nitrox_qp;
struct nitrox_softreq;

enum nitrox_comp_op {
	NITROX_COMP_OP_DECOMPRESS,
	NITROX_COMP_OP_COMPRESS,
};

enum nitrox_comp_algo {
	NITROX_COMP_ALGO_DEFLATE_DEFAULT,
	NITROX_COMP_ALGO_DEFLATE_DYNHUFF,
	NITROX_COMP_ALGO_DEFLATE_FIXEDHUFF,
	NITROX_COMP_ALGO_LZS,
};

enum nitrox_comp_level {
	NITROX_COMP_LEVEL_BEST,
	NITROX_COMP_LEVEL_MEDIUM,
	NITROX_COMP_LEVEL_LOWER,
	NITROX_COMP_LEVEL_LOWEST,
};

enum nitrox_chksum_type {
	NITROX_CHKSUM_TYPE_CRC32,
	NITROX_CHKSUM_TYPE_ADLER32,
	NITROX_CHKSUM_TYPE_NONE,
};

struct nitrox_comp_xform {
	enum nitrox_comp_op op;
	enum nitrox_comp_algo algo;
	enum nitrox_comp_level level;
	enum nitrox_chksum_type chksum_type;
};

struct nitrox_comp_stream {
	struct nitrox_comp_xform xform;
	int window_size;
	char context[NITROX_DECOMP_CTX_SIZE] __rte_aligned(8);
	char history_window[NITROX_CONSTANTS_MAX_SEARCH_DEPTH] __rte_aligned(8);
};

int nitrox_process_comp_req(struct rte_comp_op *op, struct nitrox_softreq *sr);
int nitrox_check_comp_req(struct nitrox_softreq *sr, struct rte_comp_op **op);
void *nitrox_comp_instr_addr(struct nitrox_softreq *sr);
struct rte_mempool *nitrox_comp_req_pool_create(struct rte_compressdev *cdev,
					       uint32_t nobjs, uint16_t qp_id,
					       int socket_id);
void nitrox_comp_req_pool_free(struct rte_mempool *mp);

#endif /* _NITROX_COMP_REQMGR_H_ */

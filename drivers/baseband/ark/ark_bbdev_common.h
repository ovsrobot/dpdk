/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2016-2021 Atomic Rules LLC
 */

#ifndef _ARK_BBDEV_COMMON_H_
#define _ARK_BBDEV_COMMON_H_

#include "ark_pktchkr.h"
#include "ark_pktdir.h"
#include "ark_pktgen.h"
#include "ark_bbext.h"

#define ARK_MAX_ARG_LEN 256

/* Acceptable params for ark BBDEV devices */
/*
 * The packet generator is a functional block used to generate packet
 * patterns for testing.  It is not intended for nominal use.
 */
#define ARK_BBDEV_PKTGEN_ARG "Pkt_gen"

/*
 * The packet checker is a functional block used to verify packet
 * patterns for testing.  It is not intended for nominal use.
 */
#define ARK_BBDEV_PKTCHKR_ARG "Pkt_chkr"

/*
 * The packet director is used to select the internal ingress and
 * egress packets paths during testing.  It is not intended for
 * nominal use.
 */
#define ARK_BBDEV_PKTDIR_ARG "Pkt_dir"


#define def_ptr(type, name) \
	union type {		   \
		uint64_t *t64;	   \
		uint32_t *t32;	   \
		uint16_t *t16;	   \
		uint8_t  *t8;	   \
		void     *v;	   \
	} name

/*
 * Structure to store private data for each PF/VF instance.
 */
struct ark_bbdevice {
	/* Our Bar 0 */
	uint8_t *bar0;

	/* Application Bar needed for extensions */
	uint8_t *a_bar;

	/* rte baseband device */
	struct rte_bbdev *bbdev;

	/* Arkville hardware block offsets */
	def_ptr(sys_ctrl, sysctrl);
	def_ptr(pkt_gen, pktgen);
	def_ptr(mpu_rx, mpurx);
	def_ptr(UDM, udm);
	def_ptr(mpu_tx, mputx);
	def_ptr(DDM, ddm);
	def_ptr(pkt_dir, pktdir);
	def_ptr(pkt_chkr, pktchkr);
	struct ark_rqpace_t *rqpacing;

	/* Pointers to packet generator and checker */
	int start_pg;
	ark_pkt_gen_t pg;
	ark_pkt_chkr_t pc;
	ark_pkt_dir_t pd;

	/* Packet generator/checker args */
	char pkt_gen_args[ARK_MAX_ARG_LEN];
	char pkt_chkr_args[ARK_MAX_ARG_LEN];
	uint32_t pkt_dir_v;

	int started;
	unsigned int max_nb_queues;  /**< Max number of queues */

	void *d_handle;
	struct arkbb_user_ext user_ext;
	void *user_data;

};


/* Log message for baseband PMD */
extern int ark_bbdev_logtype;

/* Helper macro for logging */
#define ARK_BBDEV_LOG(level, fmt, ...) \
	rte_log(RTE_LOG_ ## level, ark_bbdev_logtype, \
		"ARK_BBD: " fmt "\n", ##__VA_ARGS__)

int parse_ark_bbdev_params(const char *argv, struct ark_bbdevice *dev);

#endif

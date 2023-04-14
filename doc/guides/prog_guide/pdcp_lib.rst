..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(C) 2023 Marvell.

PDCP Protocol Processing Library
================================

DPDK provides a library for PDCP protocol processing. The library utilizes
other DPDK libraries such as cryptodev, reorder, etc., to provide the
application with a transparent and high performant PDCP protocol processing
library.

The library abstracts complete PDCP protocol processing conforming to
``ETSI TS 138 323 V17.1.0 (2022-08)``.
https://www.etsi.org/deliver/etsi_ts/138300_138399/138323/17.01.00_60/ts_138323v170100p.pdf

PDCP would involve the following operations,

1. Transfer of user plane data
2. Transfer of control plane data
3. Header compression
4. Uplink data compression
5. Ciphering and integrity protection

.. _figure_pdcp_functional_overview:

.. figure:: img/pdcp_functional_overview.*

   PDCP functional overview new

PDCP library would abstract the protocol offload features of the cryptodev and
would provide a uniform interface and consistent API usage to work with
cryptodev irrespective of the protocol offload features supported.

PDCP entity API
---------------

PDCP library provides following control path APIs that is used to
configure various PDCP entities,

1. ``rte_pdcp_entity_establish()``
2. ``rte_pdcp_entity_suspend()``
3. ``rte_pdcp_entity_release()``

A PDCP entity would translate to one ``rte_cryptodev_sym_session`` or
``rte_security_session`` based on the config. The sessions would be created/
destroyed while corresponding PDCP entity operations are performed.

PDCP PDU (Protocol Data Unit)
-----------------------------

PDCP PDUs can be categorized as,

1. Control PDU
2. Data PDU

Control PDUs are used for signalling between entities on either end and can be
one of the following,

1. PDCP status report
2. ROHC feedback
3. EHC feedback

Control PDUs are not ciphered or authenticated, and so such packets are not
submitted to cryptodev for processing.

Data PDUs are regular packets submitted by upper layers for transmission to
other end. Such packets would need to be ciphered and authenticated based on
the entity configuration.

PDCP packet processing API for control PDU
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Control PDUs are used in PDCP as a communication channel between transmitting
and receiving entities. When upper layer request for operations such
re-establishment, receiving PDCP entity need to prepare a status report and
send it to the other end. The API ``pdcp_ctrl_pdu_status_gen`` allows
application to request the same.

PDCP packet processing API for data PDU
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

PDCP processing is split into 2 parts. One before cryptodev processing
(``rte_pdcp_pkt_pre_process()``) and one after cryptodev processing
(``rte_pdcp_pkt_post_process()``). Since cryptodev dequeue can return crypto
operations belonging to multiple entities, ``rte_pdcp_pkt_crypto_group()``
is added to help grouping crypto operations belonging to same PDCP entity.

Lib PDCP would allow application to use same API sequence while leveraging
protocol offload features enabled by ``rte_security`` library. Lib PDCP would
internally change the handles registered for ``pre_process`` and
``post_process`` based on features enabled in the entity.

Lib PDCP would create the required sessions on the device provided in entity to
minimize the application requirements. Also, the crypto_op allocation and free
would also be done internally by lib PDCP to allow the library to create
crypto ops as required for the input packets. For example, when control PDUs are
received, no cryptodev enqueue-dequeue is expected for the same and lib PDCP
is expected to handle it differently.

Sample API usage
----------------

The ``rte_pdcp_entity_conf`` structure is used to pass the configuration
parameters for entity creation.

.. literalinclude:: ../../../lib/pdcp/rte_pdcp.h
   :language: c
   :start-after: Structure rte_pdcp_entity_conf 8<
   :end-before: >8 End of structure rte_pdcp_entity_conf.

.. code-block:: c

	struct rte_mbuf **out_mb, *pkts[MAX_BURST_SIZE];
	struct rte_crypto_op *cop[MAX_BURST_SIZE];
	struct rte_pdcp_group grp[MAX_BURST_SIZE];
	struct rte_pdcp_entity *pdcp_entity;
	int nb_max_out_mb, ret, nb_grp;
	uint16_t nb_ops;

	/* Create PDCP entity */
	pdcp_entity = rte_pdcp_entity_establish(&conf);

	/**
	 * Allocate buffer for holding mbufs returned during PDCP suspend,
	 * release & post-process APIs.
	 */

	/* Max packets that can be cached in entity + burst size */
	nb_max_out_mb = pdcp_entity->max_pkt_cache + MAX_BURST_SIZE;
	out_mb = rte_malloc(NULL, nb_max_out_mb * sizeof(uintptr_t), 0);
	if (out_mb == NULL) {
		/* Handle error */
	}

	while (1) {
		/* Receive packet and form mbuf */

		/**
		 * Prepare packets for crypto operation. Following operations
		 * would be done,
		 *
		 * Transmitting entity/UL (only data PDUs):
		 *  - Perform compression
		 *  - Assign sequence number
		 *  - Add PDCP header
		 *  - Create & prepare crypto_op
		 *  - Prepare IV for crypto operation (auth_gen, encrypt)
		 *  - Save original PDCP SDU (during PDCP re-establishment,
		 *    unconfirmed PDCP SDUs need to crypto processed again and
		 *    transmitted/re-transmitted)
		 *
		 *  Receiving entity/DL:
		 *  - Any control PDUs received would be processed and
		 *    appropriate actions taken. If data PDU, continue.
		 *  - Determine sequence number (based on HFN & per packet SN)
		 *  - Prepare crypto_op
		 *  - Prepare IV for crypto operation (decrypt, auth_verify)
		 */
		nb_success = rte_pdcp_pkt_pre_process(pdcp_entity, pkts, cop,
						      nb_rx, &nb_err);
		if (nb_err != 0) {
			/* Handle error packets */
		}

		if ((rte_cryptodev_enqueue_burst(dev_id, qp_id, cop, nb_success)
				!= nb_success) {
			/* Retry for enqueue failure packets */
		}

		...

		nb_ops = rte_cryptodev_dequeue_burst(dev_id, qp_id, cop,
						  MAX_BURST_SIZE);
		if (nb_ops == 0)
			continue;

		/**
		 * Received a burst of completed crypto ops from cryptodev. It
		 * may belong to various entities. Group similar ones together
		 * for entity specific post-processing.
		 */

		/**
		 * Groups similar entities together. Frees crypto op and based
		 * on crypto_op status, set mbuf->ol_flags which would be
		 * checked in rte_pdcp_pkt_post_process().
		 */
		nb_grp = rte_pdcp_pkt_crypto_group(cop, pkts, grp, ret);

		for (i = 0; i != nb_grp; i++) {

			/**
			 * Post process packets after crypto completion.
			 * Following operations would be done,
			 *
			 *  Transmitting entity/UL:
			 *  - Check crypto result
			 *
			 *  Receiving entity/DL:
			 *  - Check crypto operation status
			 *  - Check for duplication (if yes, drop duplicate)
			 *  - Perform decompression
			 *  - Trim PDCP header
			 *  - Hold packet (SDU) for in-order delivery (return
			 *    completed packets as and when sequence is
			 *    completed)
			 *  - If not in sequence, cache the packet and start
			 *    t-Reordering timer. When timer expires, the
			 *    packets need to delivered to upper layers (not
			 *    treated as error packets).
			 */
			nb_success = rte_pdcp_pkt_post_process(grp[i].id.ptr,
							       grp[i].m, out_mb,
							       grp[i].cnt,
							       &nb_err);
			if (nb_err != 0) {
				/* Handle error packets */
			}

			/* Perform additional operations */

			/**
			 * Transmitting entity/UL
			 * - If duplication is enabled, duplicate PDCP PDUs
			 * - When lower layers confirm reception of a PDCP PDU,
			 *   it should be communicated to PDCP layer so that
			 *   PDCP can drop the corresponding SDU
			 */
		}
	}


Supported features
------------------

- 12 bit & 18 bit sequence numbers
- Uplink & downlink traffic
- HFN increment
- IV generation as required per algorithm
- Control PDU generation

Supported ciphering algorithms
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- NULL
- AES-CTR
- SNOW3G-CIPHER
- ZUC-CIPHER

Supported integrity protection algorithms
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- NULL
- AES-CMAC
- SNOW3G-AUTH
- ZUC-AUTH

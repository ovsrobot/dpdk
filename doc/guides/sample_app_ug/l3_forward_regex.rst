..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(C) 2020 Marvell International Ltd.

L3 Forwarding Regex Sample Application
======================================

The L3 Forwarding with Regex application is a simple example of packet processing using DPDK Regex framework.
The application performs L3 LPM based forwarding while using Regex framework for pre-filtering decision.

Overview
--------

The application demonstrates the use of the Regex libraries in DPDK to implement packet forwarding.
The initialization is very similar to those of the :doc:`l3_forward`.
There is also additional initialization of Regex device and configuration per lcore.
The main difference from the L3 Forwarding sample application is that this application introduces
Regex based pre-filtering decision done before LPM lookup.
Thus, packet can be dropped or flagged before the forwarding decision.

In the sample application, only IPv4 forwarding is supported as of now.

Compiling the Application
-------------------------

To compile the sample application see :doc:`compiling`.

The application is located in the ``l3fwd-regex`` sub-directory.

Running the Application
-----------------------

The application has a number of command line options similar to l3fwd::

    ./l3fwd-regex [EAL options] -- -p PORTMASK
                                   [-P]
                                   --config (port,queue,lcore,regex-dev,regex-q)[,(port,queue,lcore,regex-dev,regex-q)]
                                   [--regex-rule-db-file FILENAME
                                   [--regex-drop]
                                   [--eth-dest=X,MM:MM:MM:MM:MM:MM]
                                   [--enable-jumbo [--max-pkt-len PKTLEN]]
                                   [--no-numa]
                                   [--parse-ptype]
                                   [--per-port-pool]
                                   [--regex-drop]
                                   [--regex-debug]

Where,

* ``-p PORTMASK:`` Hexadecimal bitmask of ports to configure

* ``-P:`` Optional, sets all ports to promiscuous mode so that packets are accepted regardless of the packet's Ethernet MAC destination address.
  Without this option, only packets with the Ethernet MAC destination address set to the Ethernet address of the port are accepted.

* ``--config (port,queue,lcore,regex-dev,regex-q)[,(port,queue,lcore,regex-dev,regex-q)]:`` Determines which queues from which ports are mapped
  to which cores, and which Regex device and queues to use.

* ``--regex-rule-db-file FILENAME:`` prebuilt rule database to configure Regex device with.

* ``--eth-dest=X,MM:MM:MM:MM:MM:MM:`` Optional, ethernet destination for port X.

* ``--enable-jumbo:`` Optional, enables jumbo frames.

*   --max-pkt-len: Optional, under the premise of enabling jumbo, maximum packet length in decimal (64-9600).

* ``--no-numa:`` Optional, disables numa awareness.

* ``--parse-ptype:`` Set to use software to analyze packet type.

* ``--per-port-pool:`` Optional, set to use independent buffer pools per port. Without this option, single buffer pool is used for all ports.

* ``--regex-drop:`` Enable Regex decision drop on match.

* ``--regex-debug:`` Enable Regex debug printing.

See :doc:`l3_forward` for details.
The L3fwd-regex example reuses the L3fwd command line options.

Refer to the *DPDK Getting Started Guide* for general information on running applications and the Environment Abstraction Layer (EAL) options.

.. _l3_fwd_regex_explanation:

Explanation
-----------

The following sections provide some explanation of the sample application code.
As mentioned in the overview section, the initialization is similar to that of the :doc:`l3_forward`.
Run-time path though similar in functionality to that of :doc:`l3_forward`, includes a Regex based pre-filtering stage before forwarding.
The following sections describe aspects that are specific to the L3 Forwarding Regex sample application.

Regex Library Initialization
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The Regex library is initialized during the l3fwd poll resource setup.
The Regex device is configured with the input rule data base and each queue
that was mapped with ``--config`` is setup.

.. code-block:: c

    /* ... */
    ret = rte_regexdev_info_get(dev_id, &dev_info);
    /* ... */

    cfg.dev_cfg_flags = 0;
    cfg.nb_max_matches = dev_info.max_matches;
    cfg.nb_queue_pairs = nb_queue_pairs;
    cfg.nb_rules_per_group = dev_info.max_rules_per_group;
    cfg.nb_groups = dev_info.max_groups;
    cfg.rule_db = conf->rule_db;
    cfg.rule_db_len = conf->rule_db_len;
    ret = rte_regexdev_configure(dev_id, &cfg);
    /* ... */

    qp_conf.qp_conf_flags = 0;
    qp_conf.nb_desc = 8192;
    qp_conf.cb = NULL;
    for (i = 0; i < nb_queue_pairs; i++) {
        ret = rte_regexdev_queue_pair_setup(dev_id, i, &qp_conf);
        /* ... */
        }
    }

After device and queue configuration there is a per lcore configuration,
where a ``rte_regex_ops`` pool is created and initialized.

.. code-block:: c

    /* ... */
    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        if (rte_lcore_is_enabled(lcore_id) == 0)
            continue;
            /* ... */
        ret = regex_lcore_init(lcore_id, qconf->regex_dev_id,
                qconf->regex_qp_id);
        /* ... */
    }

.. code-block:: c

    int
    regex_lcore_init(uint32_t lcore_id, uint32_t dev_id, uint32_t qp_id)
    {
        uint32_t i;

        regex_lcore_conf[lcore_id].qp_id = qp_id;
        regex_lcore_conf[lcore_id].dev_id = dev_id;

        memset(&regex_lcore_params[lcore_id].stats, 0,
                sizeof(struct regex_stats));

        regex_lcore_conf[lcore_id].ops = rte_malloc("regex_ops",
                REGEX_NB_OPS*sizeof(struct rte_regex_ops *),
                0);
        /* ... */
        regex_lcore_conf[lcore_id].ops_pool = rte_malloc("regex_ops_pool",
                REGEX_NB_OPS*sizeof(struct rte_regex_ops *),
                0);
        /* ... */
        for (i = 0; i < REGEX_NB_OPS; i++) {
            regex_lcore_conf[lcore_id].ops_pool[i] = rte_malloc("",
                    REGEX_OPS_DATA_SIZE, 0);
            /* ... */
        }
        regex_lcore_params[lcore_id].ops_head = 0;
        regex_lcore_params[lcore_id].ops_tail = 0;
        regex_lcore_params[lcore_id].ops_avail = REGEX_NB_OPS;

        return 0;
    }

Packet Forwarding with Regex
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

As part of slave lcores main loop, after packets are received from network port,
they are sent to the Regex device to be matched against the programmed Regex rules.
After that the REgex device is polled for responses during which the finished ops are checked for matches and an ops that had a match is counted.
The finished Regex ops are sent to the forwarding decision.

.. note::

    packets that had a match will be dropped during the forwarding decision
    if ``--regex-drop`` was given as an input to the application.

.. code-block:: c

    /* Main processing loop */

    /* ... */

     * Read packet from RX queues
     */
    for (i = 0; i < qconf->n_rx_queue; ++i) {
        portid = qconf->rx_queue_list[i].port_id;
        queueid = qconf->rx_queue_list[i].queue_id;
        nb_rx = rte_eth_rx_burst(portid, queueid, pkts_burst,
            MAX_PKT_BURST);
        if (nb_rx == 0)
            continue;
        nb_ops = regex_enqueue_burst_ops(regex_dev_id,
                lcore_id, regex_qp_id,
                pkts_burst, nb_rx);
        /* ... */

        regex_nb_ops += nb_ops;

        deq_cnt = regex_dequeue_burst_ops(regex_dev_id,
                lcore_id, regex_qp_id,
                pkts_burst, REGEX_NB_OPS);
        if (deq_cnt) {
            l3fwd_lpm_no_opt_send_packets(deq_cnt,
                    pkts_burst,
                    portid, qconf);
            regex_nb_ops -= deq_cnt;
        }

    }

During the Regex ops response processing, if ``--regex-drop`` was given as an input to the application,
the packet is marked to be dropped, by setting ``mbuf->packet_type = RTE_PTYPE_UNKNOWN``.
Because during the forwarding decision non-IP packets are dropped.

.. code-block:: c

    l3fwd_lpm_simple_forward(struct rte_mbuf *m, uint16_t portid,
            struct lcore_conf *qconf)
    {
        /* ... */
        if (RTE_ETH_IS_IPV4_HDR(m->packet_type)) {
            /* ... */
        } else if (RTE_ETH_IS_IPV6_HDR(m->packet_type)) {
            /* ... */
        } else {
            /* Free the mbuf that contains non-IPV4/IPV6 packet */
            rte_pktmbuf_free(m);
        }
    }

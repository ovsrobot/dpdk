..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2025 Stephen Hemminger

Port Mirroring API
==================


Overview
--------

The Ethdev port mirror API is a feature usefel for passive network analysis
and monitoring. `Port mirroring`_ is a common feature of network switches;
it is known as SPAN (Switch Port Analyzer) on Cisco terminology.
Mirroring is a feature in the ethdev layer that copies
some or all of the packets passing through a port.

Port mirroring can be used for analyze and debugging packets or
traffic analysis.

Mirroring is implemented in the ethdev layer and copies packets
before they are seen by the network driver (PMD).
On transmit packets are copied after the transmit callbacks and
just before passing to the network driver.
On Receive packets are copied when they are received from
the network driver before any receive callbacks.


Implementation
--------------

Creating a port mirror is done by the *rte_eth_add_mirror()* function.
The ``struct rte_eth_mirror_conf`` controls the settings of the new
mirror.

.. code-block:: c

  struct rte_eth_mirror_conf {
        struct rte_mempool *mp; /**< Memory pool for copies, If NULL then cloned. */
        struct rte_bpf_prm *filter; /**< Optional packet filter */
        uint32_t snaplen;       /**< Upper limit on number of bytes to copy */
        uint32_t flags;         /**< bitmask of RTE_ETH_MIRROR_XXX_FLAG's */
        uint16_t target;        /**< Destination port */
  };


The ``target`` field is ethdev port which will be used as the output
for the copied packets. The ``flags`` field is used to control whether
packets are mirrored on transmit (egress), receive (ingress) or both.
The ``filter`` is an optional BPF filter useful for selecting a subset
of the packets to be mirrored.

Limitations
-----------

There are some limitations to using port mirroring.

- The port being used for mirroring should not be confused with active ports
  used for other traffic. The port ownership API can be used to solve this.

- There is some performance impact when using port mirroring. The overhead
  of copying packets and sending on a the target port can be noticeable.

- Some packets maybe lost if the target port can not keep up with the
  mirrored traffic. This can be observed with the ``rte_eth_mirror_stats``.

- The API restricts mirroring of target ports to prevent packet loops.

.. _Port Mirroring: https://en.wikipedia.org/wiki/Port_mirroring

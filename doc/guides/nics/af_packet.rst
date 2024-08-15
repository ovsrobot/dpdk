..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2018 Intel Corporation.

AF_PACKET Poll Mode Driver
==========================

The AF_PACKET socket in Linux allows an application to receive and send raw
packets. This Linux-specific PMD binds to an AF_PACKET socket and allows
a DPDK application to send and receive raw packets through the Kernel.

In order to improve Rx and Tx performance this implementation makes use of
PACKET_MMAP, which provides a mmapped ring buffer, shared between user space
and kernel, that's used to send and receive packets. This helps reducing system
calls and the copies needed between user space and Kernel.

The PACKET_FANOUT_HASH behavior of AF_PACKET is used for frame reception.

Options and inherent limitations
--------------------------------

The following options can be provided to set up an af_packet port in DPDK.
Some of these, in turn, will be used to configure the PACKET_MMAP settings.

*   ``iface`` - name of the Kernel interface to attach to (required);
*   ``qpairs`` - number of Rx and Tx queues (optional, default 1);
*   ``qdisc_bypass`` - set PACKET_QDISC_BYPASS option in AF_PACKET (optional,
    disabled by default);
*   ``blocksz`` - PACKET_MMAP block size (optional, default 4096);
*   ``framesz`` - PACKET_MMAP frame size (optional, default 2048B; Note: multiple
    of 16B);
*   ``framecnt`` - PACKET_MMAP frame count (optional, default 512).
*   ``explicit_flush`` - enable two stage packet transmit.

Because this implementation is based on PACKET_MMAP, and PACKET_MMAP has its
own pre-requisites, it should be noted that the inner workings of PACKET_MMAP
should be carefully considered before modifying some of these options (namely,
``blocksz``, ``framesz`` and ``framecnt`` above).

As an example, if one changes ``framesz`` to be 1024B, it is expected that
``blocksz`` is set to at least 1024B as well (although 2048B in this case would
allow two "frames" per "block").

When ``explicit_flush`` is enabled, then the PMD will temporary buffer mbuf in a
ring buffer in the PMD until ``rte_eth_tx_done_cleanup`` is called on the TX queue.

This restriction happens because PACKET_MMAP expects each single "frame" to fit
inside of a "block". And although multiple "frames" can fit inside of a single
"block", a "frame" may not span across two "blocks".

For the full details behind PACKET_MMAP's structures and settings, consider
reading the `PACKET_MMAP documentation in the Kernel
<https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt>`_.

Prerequisites
-------------

This is a Linux-specific PMD, thus the following prerequisites apply:

*  A Linux Kernel;
*  A Kernel bound interface to attach to (e.g. a tap interface).

Set up an af_packet interface
-----------------------------

The following example will set up an af_packet interface in DPDK with the
default options described above (blocksz=4096B, framesz=2048B and
framecnt=512):

.. code-block:: console

    --vdev=eth_af_packet0,iface=tap0,blocksz=4096,framesz=2048,framecnt=512,qpairs=1,qdisc_bypass=0,explicit_flush=1

Features and Limitations
------------------------

* The PMD will re-insert the VLAN tag transparently to the packet if the kernel
  strips it, as long as the ``RTE_ETH_RX_OFFLOAD_VLAN_STRIP`` is not enabled by the
  application.
* The PMD relies on send_to() system call to transmit packets from the PACKET_MMAP socket.
  This system call can cause head-in-line blocking. Hence, it's advantageous to buffer the
  packets in the drivers instead of immediately triggering packet transmits on calling
  ``rte_eth_tx_burst()``. Therefore, the PMD splits the functionality of ``rte_eth_tx_burst()``
  into two functional stages, where ``rte_eth_tx_burst()`` causes packets to be  be buffered
  in the driver, and subsequent call to ``rte_eth_tx_done_cleanup()`` triggers the actual
  packet transmits. With such disaggregated PMD design, it is possible to call
  ``rte_eth_tx_burst()`` on workers and trigger tramists (by calling
  ``rte_eth_tx_done_cleanup()``) from a control plane worker and eliminate
  head-in-line blocking.
* To enable the two stage packet transmit, the PMD should be started with explicit_flush=1
  (Default explicit_flush=0).
* When calling ``rte_eth_tx_done_cleanup()`` the free_cnt parameter has no effect on how
  many packets are flushed. The PMD will flush all the packets present in the buffer.

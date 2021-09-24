..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2018 Intel Corporation.

AF_PACKET Poll Mode Driver
==========================

The AF_PACKET socket in Linux allows an application to receive and send raw
packets. This Linux-specific PMD driver binds to an AF_PACKET socket and allows
a DPDK application to send and receive raw packets through the Kernel.

In order to improve Rx and Tx performance this implementation makes use of
PACKET_MMAP, which provides a mmap'ed ring buffer, shared between user space
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

Because this implementation is based on PACKET_MMAP, and PACKET_MMAP has its
own pre-requisites, it should be noted that the inner workings of PACKET_MMAP
should be carefully considered before modifying some of these options (namely,
``blocksz``, ``framesz`` and ``framecnt`` above).

As an example, if one changes ``framesz`` to be 1024B, it is expected that
``blocksz`` is set to at least 1024B as well (although 2048B in this case would
allow two "frames" per "block").

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

    --vdev=eth_af_packet0,iface=tap0,blocksz=4096,framesz=2048,framecnt=512,qpairs=1,qdisc_bypass=0

Features and Limitations of the af_packet PMD
---------------------------------------------

Since the following commit, the Linux kernel strips the vlan tag

.. code-block:: console

    commit bcc6d47903612c3861201cc3a866fb604f26b8b2
    Author: Jiri Pirko <jpirko@xxxxxxxxxx>
    Date:   Thu Apr 7 19:48:33 2011 +0000

     net: vlan: make non-hw-accel rx path similar to hw-accel

Running on such a kernel results in receiving untagged frames while using
the af_packet PMD. Fortunately, the stripped information is still available
for use in ``mbuf->vlan_tci``, and applications could check ``PKT_RX_VLAN_STRIPPED``.

However, we currently don't have a way to describe offloads which can't be
disabled by PMDs, and this creates an inconsistency with the way applications
expect the PMD offloads to work, and requires them to be aware of which
underlying driver they use.

Since release 21.11 the af_packet PMD will implement support for the
``DEV_RX_OFFLOAD_VLAN_STRIP`` offload, and users can control the desired vlan
stripping behavior.

It's important to note that the default case will change. If previously,
the vlan tag was stripped, if the application now requires the same behavior,
it will need to configure ``rxmode.offloads`` with ``DEV_RX_OFFLOAD_VLAN_STRIP``.

The PMD driver will re-insert the vlan tag transparently to the application
if the kernel strips it, as long as the ``DEV_RX_OFFLOAD_VLAN_STRIP`` is not
enabled.

.. code-block:: console

    port_conf.rxmode.offloads |= DEV_RX_OFFLOAD_VLAN_STRIP

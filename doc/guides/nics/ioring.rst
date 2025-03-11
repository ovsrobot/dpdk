..  SPDX-License-Identifier: BSD-3-Clause

IORING Poll Mode Driver
=======================

The IORING Poll Mode Driver (PMD) is a simplified and improved version of the TAP PMD. It is a
virtual device that uses Linux ioring to inject packets into the Linux kernel.
It is useful when writing DPDK applications, that need to support interaction
with the Linux TCP/IP stack for control plane or tunneling.

The IORING PMD creates a kernel network device that can be
managed by standard tools such as ``ip`` and ``ethtool`` commands.

From a DPDK application, the IORING device looks like a DPDK ethdev.
It supports the standard DPDK API's to query for information, statistics,
and send/receive packets.

Requirements
------------

The IORING requires the io_uring library (liburing) which provides the helper
functions to manage io_uring with the kernel.

For more info on io_uring, please see:

https://kernel.dk/io_uring.pdf


Arguments
---------

IORING devices are created with the command line ``--vdev=net_ioring0`` option.
This option may be specified more than once by repeating with a different ``net_ioringX`` device.

By default, the Linux interfaces are named ``enio0``, ``enio1``, etc.
The interface name can be specified by adding the ``iface=foo0``, for example::

   --vdev=net_ioring0,iface=io0 --vdev=net_ioring1,iface=io1, ...

The PMD inherits the MAC address assigned by the kernel which will be
a locally assigned random Ethernet address.

Normally, when the DPDK application exits, the IORING device is removed.
But this behavior can be overridden by the use of the persist flag, example::

  --vdev=net_ioring0,iface=io0,persist ...


Multi-process sharing
---------------------

The IORING device does not support secondary process (yet).


Limitations
-----------

- IO uring requires io_uring support. This was add in Linux kernl version 5.1
  Also, IO uring maybe disabled in some environments or by security policies.

- Since IORING device uses a file descriptor to talk to the kernel,
  the same number of queues must be specified for receive and transmit.

- No flow support. Receive queue selection for incoming packets is determined
  by the Linux kernel. See kernel documentation for more info:
  https://www.kernel.org/doc/html/latest/networking/scaling.html

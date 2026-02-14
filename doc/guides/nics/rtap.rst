..  SPDX-License-Identifier: BSD-3-Clause

RTAP Poll Mode Driver
=======================

The RTAP Poll Mode Driver (PMD) is similar to the TAP PMD. It is a
virtual device that uses Linux io_uring for efficient packet I/O with
the Linux kernel.
It is useful when writing DPDK applications that need to support interaction
with the Linux TCP/IP stack for control plane or tunneling.

The RTAP PMD creates a kernel network device that can be
managed by standard tools such as ``ip`` and ``ethtool`` commands.

From a DPDK application, the RTAP device looks like a DPDK ethdev.
It supports the standard DPDK APIs to query for information, statistics,
and send/receive packets.

Features
--------

- Uses io_uring for asynchronous packet I/O via read/write and readv/writev
- TX offloads: multi-segment, UDP checksum, TCP checksum, TCP segmentation (TSO)
- RX offloads: UDP checksum, TCP checksum, TCP LRO, scatter
- Virtio net header support for offload negotiation with the kernel
- Multi-queue support (up to 128 queues)
- Multi-process support (secondary processes receive queue fds from primary)
- Link state change notification via netlink
- Rx interrupt support for power-aware applications (eventfd per queue)
- Promiscuous and allmulticast mode
- MAC address configuration
- MTU update
- Link up/down control
- Basic and per-queue statistics

Requirements
------------

- **liburing >= 2.0**.  Earlier versions have known security and build issues.

- The kernel must support ``IORING_ASYNC_CANCEL_ALL`` (upstream since 5.19).
  The meson build checks for this symbol and will not build the driver
  if the installed kernel headers do not provide it.  Because enterprise
  distributions backport features independently of version numbers,
  the driver avoids hard-coding a kernel version check.

Known working distributions:

- Debian 12 (Bookworm) or later
- Ubuntu 24.04 (Noble) or later
- Fedora 37 or later
- SUSE Linux Enterprise 15 SP6 or later / openSUSE Tumbleweed

RHEL 9 ships io_uring only as a Technology Preview (disabled by default)
and is not supported.

For more info on io_uring, please see:

- `io_uring on Wikipedia <https://en.wikipedia.org/wiki/Io_uring>`_
- `liburing on GitHub <https://github.com/axboe/liburing>`_


Arguments
---------

RTAP devices are created with the ``--vdev=net_rtap0`` command line option.
Multiple devices can be created by repeating the option with different device names
(``net_rtap1``, ``net_rtap2``, etc.).

By default, the Linux interfaces are named ``rtap0``, ``rtap1``, etc.
The interface name can be specified by adding the ``iface=foo0``, for example::

   --vdev=net_rtap0,iface=io0 --vdev=net_rtap1,iface=io1 ...

The PMD inherits the MAC address assigned by the kernel which will be
a locally assigned random Ethernet address.

Normally, when the DPDK application exits, the RTAP device is removed.
But this behavior can be overridden by the use of the persist flag, which
causes the kernel network interface to survive application exit. Example::

  --vdev=net_rtap0,iface=io0,persist ...


Limitations
-----------

- The kernel must have io_uring support with ``IORING_ASYNC_CANCEL_ALL``
  (upstream since 5.19, but may be backported by distributions).
  io_uring support may also be disabled in some environments or by security policies
  (for example, Docker disables io_uring in its default seccomp profile,
  and RHEL 9 disables it via ``kernel.io_uring_disabled`` sysctl).

- Since RTAP device uses a file descriptor to talk to the kernel,
  the same number of queues must be specified for receive and transmit.

- The maximum number of queues is 128.

- No flow support. Receive queue selection for incoming packets is determined
  by the Linux kernel. See kernel documentation for more info:
  https://www.kernel.org/doc/html/latest/networking/scaling.html

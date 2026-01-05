..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2024 FreeBSD Foundation

BPF Poll Mode Driver
====================

The BPF PMD (librte_net_bpf) provides poll mode driver support for
FreeBSD's Berkeley Packet Filter (BPF) interface. This allows DPDK
applications to send and receive raw network packets through standard
FreeBSD network interfaces.

This driver is analogous to the AF_PACKET driver for Linux.

Features
--------

- Works with any FreeBSD network interface
- Multiple queue support (via multiple BPF device instances)
- Zero-copy mode support (on FreeBSD with BIOCSETZBUF support)
- Promiscuous mode support
- Link status detection
- Statistics collection

Build Configuration
-------------------

The BPF PMD is only available on FreeBSD systems. It is automatically
enabled when building DPDK on FreeBSD.

Runtime Configuration
---------------------

The PMD is configured via the following devargs:

- ``iface`` - (Required) The name of the network interface to bind to
- ``qpairs`` - Number of queue pairs (default: 1)
- ``bufsz`` - Size of the receive buffer in bytes (default: 65536)
- ``zerocopy`` - Enable zero-copy mode: 0 or 1 (default: 0)

Example Usage
-------------

Start a DPDK application with a BPF-based port bound to em0::

    ./dpdk-app --vdev=net_bpf,iface=em0

Start with multiple queues::

    ./dpdk-app --vdev=net_bpf,iface=em0,qpairs=2

Start with custom buffer size and zero-copy enabled::

    ./dpdk-app --vdev=net_bpf,iface=em0,bufsz=131072,zerocopy=1

Multiple Ports
--------------

Multiple BPF ports can be created to capture from different interfaces::

    ./dpdk-app --vdev=net_bpf0,iface=em0 --vdev=net_bpf1,iface=em1

Limitations
-----------

- The number of queue pairs is limited by the number of available
  /dev/bpf devices on the system
- Zero-copy mode requires FreeBSD with BPF zero-copy support
- Each queue pair requires its own BPF device file descriptor
- Write operations are unbuffered (one packet per write)

Performance Considerations
--------------------------

- Zero-copy mode provides better performance by avoiding data copies
  between kernel and userspace
- Buffer size should be tuned based on expected packet rates
- Immediate mode (BIOCIMMEDIATE) is enabled by default to minimize latency

Debugging
---------

To enable debug logging for the BPF PMD, use::

    --log-level=pmd.net.bpf:debug

System Requirements
-------------------

- FreeBSD operating system
- Read/write access to /dev/bpf devices (typically requires root or
  membership in the appropriate group)
- For promiscuous mode, appropriate privileges are required

BPF Device Configuration
------------------------

The number of available BPF devices can be checked with::

    ls /dev/bpf*

The maximum number of BPF devices can be increased via sysctl::

    sysctl net.bpf.maxbufsize
    sysctl net.bpf.bufsize

See Also
--------

- FreeBSD bpf(4) man page
- DPDK AF_PACKET PMD documentation

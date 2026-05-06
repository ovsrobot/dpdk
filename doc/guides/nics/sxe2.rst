..  SPDX-License-Identifier: BSD-3-Clause
    Copyright (C), 2025, Wuxi Stars Micro System Technologies Co., Ltd.

SXE2 Poll Mode Driver
======================

The sxe2 PMD (**librte_net_sxe2**) provides poll mode driver support for
10/25/50/100/200 Gbps Network Adapters.
The embedded switch, Physical Functions (PF),
and SR-IOV Virtual Functions (VF) are supported

Implementation details
----------------------

For security reasons and robustness, this driver only deals with virtual
memory addresses. The way resources allocations are handled by the kernel
combined with hardware specifications that allow it to handle virtual memory
addresses directly ensure that DPDK applications cannot access random
physical memory (or memory that does not belong to the current process).

This capability allows the PMD to coexist with kernel network interfaces
which remain functional, although they stop receiving unicast packets as
long as they share the same MAC address.

..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2016 Intel Corporation.

.. _pcapng_library:

Packet Capture File Writer
==========================

Pcapng is a library for creating files in Pcapng file format.
The Pcapng file format is the default capture file format for modern
network capture processing tools. It can be read by wireshark and tcpdump.

Usage
-----

Before the library can be used the function ``rte_pcapng_init``
should be called once to initialize timestamp computation.


References
----------
* Project repository  https://github.com/pcapng/pcapng/

* PCAP Next Generation (pcapng) Capture File Format
https://pcapng.github.io/pcapng/draft-tuexen-opsawg-pcapng.html

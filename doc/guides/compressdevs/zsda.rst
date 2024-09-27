..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2024 ZTE Corporation.

ZTE Storage Data Accelerator (ZSDA) Poll Mode Driver
=======================================================

The ZSDA compression PMD provides poll mode compression & decompression driver
support for the following hardware accelerator devices:

* ``ZTE Processing accelerators 1cf2``


Features
--------

ZSDA compression PMD has support for:

Compression/Decompression algorithm:

    * DEFLATE - using Fixed and Dynamic Huffman encoding

Checksum generation:

    * CRC32, Adler32

Huffman code type:

* FIXED
* DYNAMIC


Limitations
-----------

* Compressdev level 0, no compression, is not supported.
* No BSD support as BSD ZSDA kernel driver not available.
* Stateful is not supported.


Installation
------------

The ZSDA compression PMD is built by default with a standard DPDK build.

It depends on a ZSDA kernel driver, see :ref:`building_zsda`.
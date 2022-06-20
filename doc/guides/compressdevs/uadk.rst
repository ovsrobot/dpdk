..  SPDX-License-Identifier: BSD-3-Clause
    Copyright 2022-2023 Huawei Technologies Co.,Ltd. All rights reserved.
    Copyright 2022-2023 Linaro ltd.

UADK Compression Poll Mode Driver
=======================================================

UADK compression PMD provides poll mode compression & decompression driver
All compression operations are using UADK compress API.
Hardware accelerators using UADK are supposed to be supported.

Features
--------

UADK compression PMD has support for:

Compression/Decompression algorithm:

    * DEFLATE - using Fixed and Dynamic Huffman encoding

Window size support:

    * 32K

Checksum generation:

    * CRC32, Adler and combined checksum

Test steps
-----------

   .. code-block:: console

	1. Build
	cd dpdk
	mkdir build
	meson build (--reconfigure)
	cd build
	ninja
	sudo ninja install

	2. Prepare
	echo 1024 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
	echo 1024 > /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages
	echo 1024 > /sys/devices/system/node/node2/hugepages/hugepages-2048kB/nr_hugepages
	echo 1024 > /sys/devices/system/node/node3/hugepages/hugepages-2048kB/nr_hugepages
	mkdir -p /mnt/huge_2mb
	mount -t hugetlbfs none /mnt/huge_2mb -o pagesize=2MB

	2 Test with compress_uadk
	sudo dpdk-test --vdev=compress_uadk
	RTE>>compressdev_autotest
	RTE>>quit

Dependency
------------

UADK compression PMD relies on UADK library [1]

[1] https://github.com/Linaro/uadk

..  SPDX-License-Identifier: BSD-3-Clause
    Copyright 2022-2023 Huawei Technologies Co.,Ltd. All rights reserved.
    Copyright 2022-2023 Linaro ltd.

UADK Crypto Poll Mode Driver
=======================================================

UADK crypto PMD provides poll mode driver
All cryptographic operations are using UADK crypto API.
Hardware accelerators using UADK are supposed to be supported.


Features
--------

UADK crypto PMD has support for:


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

	3. Run test app

Dependency
------------

UADK crypto PMD relies on UADK library [1]

UADK is a framework for user applications to access hardware accelerators.
UADK relies on IOMMU SVA (Shared Virtual Address) feature, which share
the same page table between IOMMU and MMU.
As a result, user application can directly use virtual address for device dma,
which enhances the performance as well as easy usability.

Build & Install UADK
-----------

   .. code-block:: console

	git clone https://github.com/Linaro/uadk.git
	cd uadk
	./autogen.sh
	./configure
	make
	sudo make install

* If get error:"cannot find -lnuma", please install the libnuma-dev

[1] https://github.com/Linaro/uadk

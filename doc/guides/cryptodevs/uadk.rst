..  SPDX-License-Identifier: BSD-3-Clause
    Copyright 2022-2023 Huawei Technologies Co.,Ltd. All rights reserved.
    Copyright 2022-2023 Linaro ltd.

UADK Crypto Poll Mode Driver
=======================================================

UADK crypto PMD provides poll mode driver
All cryptographic operations are using UADK crypto API.
Support for the following hardware accelerator devices:

* ``HiSilicon Kunpeng920``
* ``HiSilicon Kunpeng930``


Features
--------

UADK crypto PMD has support for:

Cipher algorithms:

* ``RTE_CRYPTO_CIPHER_AES_ECB``
* ``RTE_CRYPTO_CIPHER_AES_CBC``
* ``RTE_CRYPTO_CIPHER_AES_XTS``
* ``RTE_CRYPTO_CIPHER_DES_CBC``

Hash algorithms:

* ``RTE_CRYPTO_AUTH_MD5``
* ``RTE_CRYPTO_AUTH_MD5_HMAC``
* ``RTE_CRYPTO_AUTH_SHA1``
* ``RTE_CRYPTO_AUTH_SHA1_HMAC``
* ``RTE_CRYPTO_AUTH_SHA224``
* ``RTE_CRYPTO_AUTH_SHA224_HMAC``
* ``RTE_CRYPTO_AUTH_SHA256``
* ``RTE_CRYPTO_AUTH_SHA256_HMAC``
* ``RTE_CRYPTO_AUTH_SHA384``
* ``RTE_CRYPTO_AUTH_SHA384_HMAC``
* ``RTE_CRYPTO_AUTH_SHA512``
* ``RTE_CRYPTO_AUTH_SHA512_HMAC``

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

	2 Test with crypto_uadk
	sudo dpdk-test --vdev=crypto_uadk (--log-level=6)
	RTE>>cryptodev_uadk_autotest
	RTE>>quit

Dependency
------------

UADK crypto PMD relies on UADK library [1]

UADK is a framework for user applications to access hardware accelerators.
UADK relies on IOMMU SVA (Shared Virtual Address) feature, which share
the same page table between IOMMU and MMU.
As a result, user application can directly use virtual address for device dma,
which enhances the performance as well as easy usability.

[1] https://github.com/Linaro/uadk

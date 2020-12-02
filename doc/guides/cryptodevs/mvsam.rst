..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2018 Marvell International Ltd.
    Copyright(c) 2018 Semihalf.
    All rights reserved.

MVSAM Crypto Poll Mode Driver
=============================

The MVSAM CRYPTO PMD (**librte_crypto_mvsam**) provides poll mode crypto driver
support by utilizing MUSDK library, which provides cryptographic operations
acceleration by using Security Acceleration Engine (EIP197) directly from
user-space with minimum overhead and high performance.

Detailed information about SoCs that use MVSAM crypto driver can be obtained here:

* https://www.marvell.com/embedded-processors/armada-70xx/
* https://www.marvell.com/embedded-processors/armada-80xx/
* https://www.marvell.com/embedded-processors/armada-3700/


Features
--------

MVSAM CRYPTO PMD has support for:

* Symmetric crypto operations: encryption/description and authentication
* Symmetric chaining crypto operations
* HW Accelerated using EIP97/EIP197b/EIP197d
* Out-of-place Scatter-gather list Input, Linear Buffers Output
* Out-of-place Linear Buffers Input, Linear Buffers Output

Cipher algorithms:

* ``RTE_CRYPTO_CIPHER_NULL``
* ``RTE_CRYPTO_CIPHER_AES_CBC``
* ``RTE_CRYPTO_CIPHER_AES_CTR``
* ``RTE_CRYPTO_CIPHER_AES_ECB``
* ``RTE_CRYPTO_CIPHER_3DES_CBC``
* ``RTE_CRYPTO_CIPHER_3DES_CTR``
* ``RTE_CRYPTO_CIPHER_3DES_ECB``

Hash algorithms:

* ``RTE_CRYPTO_AUTH_NULL``
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
* ``RTE_CRYPTO_AUTH_AES_GMAC``

AEAD algorithms:

* ``RTE_CRYPTO_AEAD_AES_GCM``

For supported feature flags please consult :doc:`overview`.

Limitations
-----------

* Hardware only supports scenarios where ICV (digest buffer) is placed just
  after the authenticated data. Other placement will result in error.

Prerequisites
-------------

- Custom Linux Kernel sources

  .. code-block:: console

     git clone https://github.com/MarvellEmbeddedProcessors/linux-marvell.git -b linux-4.4.120-armada-18.09

- Out of tree `mvpp2x_sysfs` kernel module sources

  .. code-block:: console

     git clone https://github.com/MarvellEmbeddedProcessors/mvpp2x-marvell.git -b mvpp2x-armada-18.09

- MUSDK (Marvell User-Space SDK) sources

  .. code-block:: console

     git clone https://github.com/MarvellEmbeddedProcessors/musdk-marvell.git -b musdk-release-SDK-10.3.5.0-PR2

Installation
------------

MVSAM CRYPTO PMD requires MUSDK built with EIP197 support thus following
extra option must be passed to the library configuration script:

.. code-block:: console

   --enable-sam [--enable-sam-statistics] [--enable-sam-debug]

For instructions how to build required kernel modules please refer
to `doc/musdk_get_started.txt`.

Building DPDK
-------------

Driver needs precompiled MUSDK library during compilation.
MUSDK will be installed to `usr/local` under current directory.
For the detailed build instructions please consult ``doc/musdk_get_started.txt``.

Add path to libmusdk.pc in PKG_CONFIG_PATH environment variable:

.. code-block:: console

   export PKG_CONFIG_PATH=$<musdk_install_dir>/lib/pkgconfig/:$PKG_CONFIG_PATH

Build DPDK:

.. code-block:: console

   meson build --cross-file config/arm/arm64_armada_linux_gcc
   ninja -C build



Usage Example
-------------

l2fwd-crypto example application can be used to verify MVSAM CRYPTO PMD
operation:

.. code-block:: console

   ./dpdk-l2fwd-crypto --vdev=eth_mvpp2,iface=eth0 --vdev=crypto_mvsam -- \
     --cipher_op ENCRYPT --cipher_algo aes-cbc \
     --cipher_key 00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f  \
     --auth_op GENERATE --auth_algo sha1-hmac \
     --auth_key 10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f

.. SPDX-License-Identifier: BSD-3-Clause
   Copyright 2025 The DPDK contributors

.. include:: <isonum.txt>

DPDK Release 26.03
==================

New Features
------------

* **Added custom memory allocation hooks in ACL library.**

  Added a hook API mechanism
  allowing applications to provide their own allocation and free functions
  for ACL runtime memory.

* **Updated AMD axgbe ethernet driver.**

  * Added support for V4000 Krackan2e.

* **Updated AF_PACKET ethernet driver.**

  * Added support for multi-segment mbuf reception to handle jumbo frames
    with standard mbuf sizes when scatter Rx offload is enabled.

* **Updated CESNET nfb ethernet driver.**

  * The timestamp value has been updated to make it usable.
  * The DPDK port has been changed to represent just one Ethernet port
    instead of all Ethernet ports on the NIC.
  * Added ``port`` device argument to select a subset of all ports.
  * Added firmware version, correct Ethernet link speed and maximum MTU reporting.
  * Common CESNET-NDK-based adapters have been added,
    including the FB2CGHH (Silicom Denmark) and XpressSX AGI-FH400G (Reflex CES).
  * Added support for configuration of the RS-FEC mode, link up / down state, and the Rx MTU.

* **Updated Google Virtual Ethernet (gve) driver.**

  * Added application-initiated device reset.
  * Added support for receive flow steering.

* **Updated Huawei hinic3 ethernet driver.**

  * Added support for Huawei's new SPx NICs, including SP230 and SP920 (DPU).
  * Added support for GENEVE tunnel TSO and IP-in-IP tunnel TSO on the SP230.
  * Added support for VXLAN-GPE checksum on the SP620.
  * Added support for tunnel packet outer UDP checksum.
  * Added support for QinQ on the SP620.

* **Updated Intel idpf ethernet driver.**

  * Added support for time sync features.

* **Updated Intel iavf driver.**

  * Added support for pre and post VF reset callbacks.

* **Updated Intel ice driver.**

  * Added flow API support for L2TPv2 over UDP.

* **Updated Intel idpf driver.**

  * Added AVX2 vectorized split queue Rx and Tx paths.

* **Updated Marvell cnxk net driver.**

  * Added out-of-place support for CN20K SoC.
  * Added plain packet reassembly support for CN20K SoC.
  * Added IPsec Rx inject support for CN20K SoC.

* **Updated ZTE zxdh ethernet driver.**

  * Added support for modifying queue depth.
  * Optimized queue allocation resources.
  * Added support for setting link speed and getting auto-negotiation status.
  * Added support for secondary processes.
  * Added support for GENEVE TSO and tunnel outer UDP Rx checksum.

* **Added 256-NEA/NCA/NIA algorithms in cryptodev library.**

  Added support for the following wireless algorithms:
  * NEA4, NIA4, NCA4: Snow 5G confidentiality, integrity and AEAD modes.
  * NEA5, NIA5, NCA5: AES 256 confidentiality, integrity and AEAD modes.
  * NEA6, NIA6, NCA6: ZUC 256 confidentiality, integrity and AEAD modes.

* **Updated Marvell cnxk crypto driver.**

  * Added support for Snow 5G NEA4/NIA4 and ZUC 256 NEA6/NIA6 for CN20K platform.

* **Updated openssl crypto driver.**

  * Added support for AES-XTS cipher algorithm.
  * Added support for SHAKE-128 and SHAKE-256 authentication algorithms.
  * Added support for SHA3-224, SHA3-256, SHA3-384, and SHA3-512 hash algorithms
    and their HMAC variants.

* **Added automatic deferred free on hash data overwrite.**

  When RCU is configured with a ``free_key_data_func`` callback,
  ``rte_hash_add_key_data`` now automatically defers
  freeing the old data pointer on key overwrite via the RCU defer queue.

* **Added Ctrl+L support to cmdline library.**

  Added handling of the key combination Ctrl+L
  to clear the screen before redisplaying the prompt.


Removed Items
-------------

* **Discontinued support for AMD Solarflare SFN7xxx family boards.**

  7000 series adaptors are out of support in terms of hardware.

* **Removed the SSE vector paths from some Intel drivers.**

  The SSE path was not widely used, so it was removed
  from the i40e, iavf and ice drivers.
  Each of these drivers has faster vector paths (AVX2 and AVX-512)
  which have feature parity with the SSE paths,
  and a fallback scalar path which also has feature parity.


API Changes
-----------

* **Added additional length checks for name parameter lengths.**

  Several library functions now have additional name length checks
  instead of silently truncating.

  * lpm: name must be less than ``RTE_LPM_NAMESIZE``.
  * hash: name parameter must be less than ``RTE_HASH_NAMESIZE``.
  * efd: name must be less than ``RTE_EFD_NAMESIZE``.
  * tailq: name must be less than ``RTE_TAILQ_NAMESIZE``.
  * cfgfile: name must be less than ``CFG_NAME_LEN``
    and value must be less than ``CFG_VALUE_LEN``.

* **Updated the pcapng library.**

  * The length of comment strings is now validated.
    Maximum allowable length is 2^16-1 because of the pcapng file format.


ABI Changes
-----------

* No ABI change that would break compatibility with 25.11.


Tested Platforms
----------------

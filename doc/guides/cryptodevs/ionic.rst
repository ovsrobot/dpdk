..  SPDX-License-Identifier: BSD-3-Clause
    Copyright 2021-2024 Advanced Micro Devices, Inc.

IONIC Crypto Driver
===================

The ionic crypto driver provides support for offloading cryptographic operations
to hardware cryptographic blocks on AMD Pensando server adapters.
It currently supports the below models:

- DSC-25 dual-port 25G Distributed Services Card `(pdf) <https://pensandoio.secure.force.com/DownloadFile?id=a0L4T000004IKurUAG>`__
- DSC-100 dual-port 100G Distributed Services Card `(pdf) <https://pensandoio.secure.force.com/DownloadFile?id=a0L4T000004IKuwUAG>`__
- DSC-200 dual-port 200G Distributed Services Card `(pdf) <https://www.amd.com/system/files/documents/pensando-dsc-200-product-brief.pdf>`__

Please visit the AMD Pensando web site at https://www.amd.com/en/accelerators/pensando for more information.

Device Support
--------------

The ionic crypto PMD currently supports running directly on the device's embedded
processors. It does not yet support host-side access via PCI.
For help running the PMD, please contact AMD Pensando support.

Runtime Configuration
---------------------

None


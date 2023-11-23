..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2010-2025 Intel Corporation.

.. _hugepages_different_architectures:

Hugepages Configuration for Multiple Architectures
==================================================

This section outlines the steps for configuring hugepages of various sizes on different architectures, an important aspect for optimizing DPDK performance.

Hugepages on x86 Architecture
-----------------------------

**2MB and 1G Hugepages**

- *2MB hugepages* are commonly used on x86.
- *1G hugepages* can improve performance for large-memory applications.

**Configuring 1G Hugepages**

.. code-block:: bash

    # Example GRUB configuration for 1G hugepages
    GRUB_CMDLINE_LINUX="default_hugepagesz=1G hugepagesz=1G hugepages=4"

Update GRUB and reboot after making these changes.

Hugepages on ARM Architecture
-----------------------------

ARM supports a range of hugepage sizes, such as 64KB, 512KB, and 2MB.

**Example Configuration**

.. code-block:: bash

    # Setting 2MB hugepages on ARM
    echo N > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

Replace 'N' with the number of pages needed.

Other Architectures
-------------------

Refer to architecture-specific documentation for hugepage configurations on platforms like PowerPC or MIPS.

Boot-Time Reservation of Hugepages
----------------------------------

Boot-time reservation is essential for large hugepage sizes. Modify the boot loader, such as GRUB, for this purpose:

.. code-block:: bash

    GRUB_CMDLINE_LINUX="hugepagesz=2M hugepages=512"

Regenerate the GRUB config and reboot your system.

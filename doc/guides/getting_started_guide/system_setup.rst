..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2010-2025 Intel Corporation.

.. _memory_setup:

.. |reg| unicode:: U+000AE

Setting up a System to Run DPDK Applications
============================================

This section provides step-by-step instructions for setting up your system to run DPDK applications. It covers system configurations for Linux, FreeBSD, and Windows. Each section details the necessary memory and device setups for these operating systems.

Navigate to the section that corresponds to your operating system to begin the setup process.

.. contents:: Table of Contents
   :local:

System Setup for Linux
----------------------

Memory Setup: Reserving Hugepages
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For Linux, DPDK requires hugepages be reserved for its use on the system. To check if hugepages are are on your system, you can run the following command::

        grep HugePages_Total /proc/meminfo

If hugepages are not reserved, you will need to reserve them by following these steps:

1. Determine the number of hugepages you want to allocate. For example, to allocate 1024 hugepages of 2MB each, you can use the following command::

        echo 1024 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

2. To make the hugepages configuration persistent across reboots, add the following line to your `/etc/sysctl.conf` file, adjusting the number of hugepages as needed::

        vm.nr_hugepages = 1024

3. Most distributions make hugepages available via `/dev/hugepages`, so this step may not be necessary. If you need to manually mount the hugepages filesystem, add the following line to your `/etc/fstab` file::

        nodev /mnt/huge hugetlbfs defaults 0 0

   Then, create the mount directory and mount the filesystem::

        mkdir -p /mnt/huge
        mount -a

Device Setup: VFIO
^^^^^^^^^^^^^^^^^^

VFIO is a robust and secure driver that relies on IOMMU protection.
To make use of VFIO on Linux, the ``vfio-pci`` module must be loaded:

.. code-block:: console

    sudo modprobe vfio-pci

VFIO kernel is usually present by default in all distributions,
however please consult your distribution's documentation to make sure that is the case.

To make use of full VFIO functionality,
both kernel and BIOS must support and be configured
to use IO virtualization (such as Intel\ |reg| VT-d).

.. note::

   In most cases, specifying "iommu=on" as kernel parameter should be enough to
   configure the Linux kernel to use IOMMU.

For proper operation of VFIO when running DPDK applications as a non-privileged user,
correct permissions should also be set up.
For more information, refer to :ref:`running_dpdk_apps_without_root`.

Refer to :ref:`vfio_no_iommu_mode` when there is no IOMMU available on the system.

Binding and Unbinding Network Ports to/from VFIO-PCI Module
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To bind or unbind network ports to/from the `vfio-pci` module on Linux, follow these steps:

Replace ``<module_id>`` with the appropriate module identifier.

**Unbind from current module**:
   If a device is bound to a kernel driver, unbind it:

   .. code-block:: bash

      sudo dpdk-devbind.py -u <module_id>

**Bind to vfio-pci module**:
   Bind the device to the `vfio-pci` module:

   .. code-block:: bash

      sudo dpdk-devbind.py -b vfio-pci <module_id>

System Setup for FreeBSD
------------------------

.. _loading_contigmem_module:

Memory Setup: Loading the DPDK contigmem Module
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To run a DPDK application on FreeBSD, physically contiguous memory is required. In the absence of non-transparent superpages, the included sources for the `contigmem` kernel module provides the ability to present contiguous blocks of memory for the DPDK to use. 
The ``contigmem`` module must be loaded into the running kernel before any DPDK is run.
Once DPDK is installed on the system, the module can be found in the ``/boot/modules``
directory.

The amount of physically contiguous memory along with the number of physically
contiguous blocks to be reserved by the module can be set at runtime prior to module
loading using::

    kenv hw.contigmem.num_buffers=n
    kenv hw.contigmem.buffer_size=m

The kernel environment variables can also be specified during boot by placing the
following in ``/boot/loader.conf``::

    hw.contigmem.num_buffers=n
    hw.contigmem.buffer_size=m

The variables can be inspected using the following command::

    sysctl -a hw.contigmem

The module can then be loaded using ``kldload``::

    cd /boot/modules
    kldload contigmem

Device Setup: Loading the DPDK nic_uio Module
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

After :ref:`loading_contigmem_module` on FreeBSD, the ``nic_uio`` module must also be loaded into the running kernel prior to running any DPDK application, e.g. using::

    cd /boot/modules
    kldload nic_uio

By default, the ``nic_uio`` module will take ownership of network ports if they are
recognized DPDK devices and are not owned by another module. 
However, since the FreeBSD kernel includes support, either built-in, 
or via a separate driver module, for most network card devices,
it is likely that the ports to be used are already bound to a driver other than
``nic_uio``.

To re-bind the ports to the `nic_uio` module upon loading, use the following command::

    kenv hw.nic_uio.bdfs="b:d:f,b:d:f,..."

Where a comma-separated list of selectors is set, the list must not contain any
whitespace.

The variable can also be specified during boot by placing the following into
``/boot/loader.conf``, before the previously-described ``nic_uio_load`` line::

    hw.nic_uio.bdfs="2:0:0,2:0:1"
    nic_uio_load="YES"

Binding and Unbinding Network Ports to/from nic_uio Module
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If the original driver for a network port has been compiled into the kernel, 
it is necessary to reboot FreeBSD to restore the original device binding. 
Before doing so, update or remove the ``hw.nic_uio.bdfs`` in ``/boot/loader.conf``.

If rebinding to a driver that is a loadable module, the network port binding can be
reset without rebooting. To do so, unload both the target kernel module and the
``nic_uio`` module, modify or clear the ``hw.nic_uio.bdfs`` kernel environment
(``kenv``) value, and reload the two drivers - first the original kernel driver,
and then the ``nic_uio`` driver.

Example commands to perform these steps are shown below::

    kldunload nic_uio
    kldunload <original_driver>
    kenv -u hw.nic_uio.bdfs
    kldload <original_driver>
    kldload nic_uio  # optional

System Setup for Windows
------------------------

Memory Setup: Installing Windows Modules
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Before running DPDK applications on Windows, certain kernel-mode drivers must be installed. Note that these drivers are not signed, so you'll need to disable signature enforcement. However, be cautious as this can weaken your OS security and is generally not recommended in production environments.

Device Setup: Install Drivers
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To run DPDK applications on Windows, you'll need to install specific kernel-mode drivers:

- **virt2phys**: This driver is essential for providing access to physical addresses and is mandatory for allocating physically-contiguous memory, which is required by hardware PMDs. Once loaded successfully, this driver will appear in the Device Manager as ``Virtual to physical address translator device`` under the Kernel bypass category. If DPDK cannot communicate with the driver, a warning will be printed during initialization.

- **NetUIO**: This driver provides access to device hardware resources and is mandatory for all hardware PMDs, except for the mlx5 PMD. Devices supported by NetUIO are listed in ``netuio.inf``. You can extend this list to try running DPDK with new devices.
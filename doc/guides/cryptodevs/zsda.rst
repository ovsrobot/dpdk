..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2024 ZTE Corporation.

ZSDA documentation consists of two parts:

* Details of the symmetric crypto services below.
* Details of building the common ZSDA infrastructure and the PMDs to support the
  above services. See :ref:`building_zsda` below.


Symmetric Crypto Service on ZSDA
--------------------------------

The ZSDA symmetric crypto PMD provides poll mode crypto driver
support for the following hardware accelerator devices:

* ``ZTE Processing accelerators 1cf2``

Features
~~~~~~~~



Limitations
~~~~~~~~~~~



.. _building_zsda:

Building PMDs on ZSDA
---------------------

A ZSDA device can host multiple acceleration services:

* symmetric cryptography
* data compression

These services are provided to DPDK applications via PMDs which register to
implement the corresponding cryptodev and compressdev APIs. The PMDs use
common ZSDA driver code which manages the ZSDA PCI device.


Configuring and Building the DPDK ZSDA PMDs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Further information on configuring, building and installing DPDK is described
:doc:`here <../linux_gsg/build_dpdk>`.

.. _building_zsda_config:

Build Configuration
~~~~~~~~~~~~~~~~~~~
These is the build configuration options affecting ZSDA, and its default values:

.. code-block:: console

	RTE_PMD_ZSDA_MAX_PCI_DEVICES=256

ZSDA SYM PMD has an external dependency on libcrypto, so is not built by default.

Ubuntu

.. code-block:: console

   apt install libssl-dev

RHEL

.. code-block:: console

   dnf install openssl-devel

The ZSDA compressdev PMD has no external dependencies, so is built by default.


Device and driver naming
~~~~~~~~~~~~~~~~~~~~~~~~

* The zsda cryptodev symmetric crypto driver name is "crypto_zsda".
* The zsda compressdev compress driver name is "compress_zsda".

The "rte_cryptodev_devices_get()" returns the devices exposed by either of these drivers.

* Each zsda sym crypto device has a unique name, in format
  "<pci bdf>", e.g. "0000:cc:00.3_zsda".
  This name can be passed to "rte_cryptodev_get_dev_id()" to get the device_id.

.. Note::

	The cryptodev driver name is passed to the dpdk-test-crypto-perf tool in the "-devtype" parameter.

	The zsda crypto device name is in the format of the worker parameter passed to the crypto scheduler.

* The zsda compressdev driver name is "compress_zsda".
  The rte_compressdev_devices_get() returns the devices exposed by this driver.

* Each zsda compression device has a unique name, in format
  <pci bdf>, e.g. "0000:cc:00.3_zsda".
  This name can be passed to rte_compressdev_get_dev_id() to get the device_id.


Enable VFs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Instructions for installation are below, but first an explanation of the
relationships between the PF/VF devices and the PMDs visible to
DPDK applications.

Each ZSDA PF device exposes a number of VF devices. Each VF device can
enable one symmetric cryptodev PMD and/or one compressdev PMD.

These ZSDA PMDs share the same underlying device and pci-mgmt code, but are
enumerated independently on their respective APIs and appear as independent
devices to applications.
.. Note::

   Each VF can only be used by one DPDK process. It is not possible to share
   the same VF across multiple processes, even if these processes are using
   different acceleration services.
   Conversely one DPDK process can use one or more ZSDA VFs and can expose both
   cryptodev and compressdev instances on each of those VFs.


The examples below are based on the 1cf2 device, if you have a different device
use the corresponding values in the above table.

In BIOS ensure that SRIOV is enabled and either:

* Disable VT-d or
* Enable VT-d and set ``"intel_iommu=on iommu=pt"`` in the grub file.

you need to expose the Virtual Functions (VFs) using the sysfs file system.

First find the BDFs (Bus-Device-Function) of the physical functions (PFs) of
your device, e.g.::

    lspci -d:8050

You should see output similar to::


    cc:00.4 Processing accelerators: Device 1cf2:8050 (rev 01)
    ce:00.3 Processing accelerators: Device 1cf2:8050 (rev 01)
    d0:00.3 Processing accelerators: Device 1cf2:8050 (rev 01)
    d2:00.3 Processing accelerators: Device 1cf2:8050 (rev 01)

Enable the VFs for each PF by echoing the number of VFs per PF to the pci driver::

     echo 31 > /sys/bus/pci/device/0000:cc:00.4/sriov_numvfs
     echo 31 > /sys/bus/pci/device/0000:ce:00.3/sriov_numvfs
     echo 31 > /sys/bus/pci/device/0000:d0:00.3/sriov_numvfs
     echo 31 > /sys/bus/pci/device/0000:d2:00.3/sriov_numvfs

Check that the VFs are available for use. For example ``lspci -d:8051`` should
list 124 VF devices available.

To complete the installation follow the instructions in
`Binding the available VFs to the vfio-pci driver`_.

.. Note::

   If you see the following warning in ``/var/log/messages`` it can be ignored:
   ``IOMMU should be enabled for SR-IOV to work correctly``.

Binding the available VFs to the vfio-pci driver
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Note:

* Please note that due to security issues, the usage of older DPDK igb_uio
  driver is not recommended. This document shows how to use the more secure
  vfio-pci driver.

Unbind the VFs from the stock driver so they can be bound to the vfio-pci driver.

Bind to the vfio-pci driver
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Load the vfio-pci driver, bind the VF PCI Device id to it using the
``dpdk-devbind.py`` script then use the ``--status`` option
to confirm the VF devices are now in use by vfio-pci kernel driver,
e.g. for the 1cf2 device::

    cd to the top-level DPDK directory
    modprobe vfio-pci
    usertools/dpdk-devbind.py -b vfio-pci 0000:cc:01.4
    usertools/dpdk-devbind.py --status

Use ``modprobe vfio-pci disable_denylist=1`` from kernel 5.9 onwards.
See note in the section `Binding the available VFs to the vfio-pci driver`_
above.

Testing
~~~~~~~


Debugging
~~~~~~~~~

There are 2 sets of trace available via the dynamic logging feature:

* pmd.zsda.dp exposes trace on the data-path.
* pmd.zsda.general exposes all other trace.

pmd.zsda exposes both sets of traces.
They can be enabled using the log-level option (where 8=maximum log level) on
the process cmdline, e.g. using any of the following::

    --log-level="pmd.zsda.general,8"
    --log-level="pmd.zsda.dp,8"

.. Note::

    The global RTE_LOG_DP_LEVEL overrides data-path trace so must be set to
    RTE_LOG_DEBUG to see all the trace. This variable is in config/rte_config.h
    for meson build.
    Also the dynamic global log level overrides both sets of trace, so e.g. no
    ZSDA trace would display in this case::

	--log-level="pmd.zsda.general,8" --log-level="pmd.zsda,8"

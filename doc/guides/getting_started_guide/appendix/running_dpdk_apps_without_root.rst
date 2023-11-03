..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2010-2025 Intel Corporation.

.. _running_dpdk_apps_without_root:

Running DPDK Applications Without Root Privileges
=================================================

Although applications using the DPDK use network ports and other hardware resources
directly, with a number of small permission adjustments, 
it is possible to run these applications as a user other than “root”. 
To do so, the ownership, or permissions, on the following file system objects should be
adjusted so the user account being used to run the DPDK application has
access to them:

Linux
-----

1. **Create a DPDK User Group**: Create a new user group for DPDK and add the desired user to this group.

2. **Set Up Hugepages**: Configure hugepages for the user.

3. **Bind the NIC to a User-Space Driver**: Use the DPDK tool ``dpdk-devbind.py`` to bind the NIC to a user-space driver like ``vfio-pci`` or ``igb_uio``.

4. **Set Permissions for UIO/VFIO Devices**: Change the ownership and permissions of the UIO or VFIO devices to allow access by the DPDK user group.

5. **Run the DPDK Application**: Run the desired DPDK application as the user who has been added to the DPDK group.

FreeBSD
-------

- The userspace-io device files in ``/dev``, for example, ``/dev/uio0``, ``/dev/uio1``, and so on
- The userspace contiguous memory device: ``/dev/contigmem``


Refer to the `DPDK Release Notes <https://doc.dpdk.org/guides/rel_notes/index.html>`_ for supported applications.
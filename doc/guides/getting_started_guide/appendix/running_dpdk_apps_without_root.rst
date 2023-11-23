.. _running_dpdk_apps_without_root:

Running DPDK Applications Without Root Privileges
=================================================

It's important to note that running DPDK as non-root on Linux requires IOMMU support through vfio.

Linux
-----
To run DPDK applications without root privileges on Linux, follow these steps:

1. **Adjust Permissions for Specific Files and Directories**:

   - VFIO entries in ``/dev``, such as ``/dev/vfio/<id>``, where ``<id>`` is the VFIO group to which a device used by DPDK belongs.
   - The hugepage mount directory, typically ``/dev/hugepages``, or any alternative mount point configured by the user, e.g., ``/mnt/huge``, ``/mnt/huge_1G``.

2. **Run the DPDK Application**: Execute the desired DPDK application as the user who has been added to the DPDK group.

FreeBSD
-------
Adjust the permissions of the following files to run DPDK applications as a non-root user:

- The userspace-io device files in ``/dev``, for example, ``/dev/uio0``, ``/dev/uio1``, and so on.
- The userspace contiguous memory device: ``/dev/contigmem``.

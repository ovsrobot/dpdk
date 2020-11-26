..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2010-2014 Intel Corporation.

.. _linux_setup_script:

Quick Start Setup Script
========================

The dpdk-setup.sh script, found in the usertools subdirectory, allows the user to perform the following tasks:

*   Insert and remove VFIO kernel modules

*   Remove the DPDK IGB_UIO kernel module

*   Remove the DPDK KNI kernel module

*   Create and delete hugepages for NUMA and non-NUMA cases

*   View network port status and reserve ports for DPDK application use

*   Set up permissions for using VFIO as a non-privileged user

*   Run the test and testpmd applications

*   Look at hugepages in the meminfo

*   List hugepages in ``/mnt/huge``

Please refer to :doc:`../prog_guide/build-sdk-meson` for building DPDK.

Script Organization
-------------------

The dpdk-setup.sh script is logically organized into a series of steps that a user performs in sequence.
Each step provides a number of options that guide the user to completing the desired task.
The following is a brief synopsis of each step.

**Step 1: Setup Environment**

The user configures the Linux* environment to support the running of DPDK applications.
Hugepages can be set up for NUMA or non-NUMA systems. Any existing hugepages will be removed.
Network ports may be bound to DPDK kernel module for DPDK application use.

**Step 2: Run an Application**

The user may run the test application once the other steps have been performed.
The test application allows the user to run a series of functional tests for the DPDK.
The testpmd application, which supports the receiving and sending of packets, can also be run.

**Step 3: Examining the System**

This step provides some tools for examining the status of hugepage mappings.

**Step 4: System Cleanup**

The final step has options for restoring the system to its original state.

Use Cases
---------

The following are some example of how to use the dpdk-setup.sh script.
The script should be run using the source command.
Some options in the script prompt the user for further data before proceeding.

.. warning::

    The dpdk-setup.sh script should be run with root privileges.

.. code-block:: console

    source usertools/dpdk-setup.sh

    ------------------------------------------------------------------------

    RTE_SDK exported as /home/user/rte

    ------------------------------------------------------------------------

    Step 1: Setup linux environment

    ------------------------------------------------------------------------

    [1] Insert VFIO module

    [2] Setup hugepage mappings for non-NUMA systems

    [3] Setup hugepage mappings for NUMA systems

    [4] Display current Ethernet device settings

    [5] Bind Ethernet device to IGB UIO module

    [6] Bind Ethernet device to VFIO module

    [7] Setup VFIO permissions

    ------------------------------------------------------------------------

    Step 2: Run test application for linux environment

    ------------------------------------------------------------------------

    [8] Run test application ($RTE_TARGET/app/test)

    [9] Run testpmd application in interactive mode ($RTE_TARGET/app/testpmd)

    ------------------------------------------------------------------------

    Step 3: Other tools

    ------------------------------------------------------------------------

    [10] List hugepage info from /proc/meminfo

    ------------------------------------------------------------------------

    Step 4: Uninstall and system cleanup

    ------------------------------------------------------------------------

    [11] Unbind NICs from IGB UIO driver

    [12] Remove IGB UIO module

    [13] Remove VFIO module

    [14] Remove KNI module

    [15] Remove hugepage mappings

    [16] Exit Script

    Option:

The following selection demonstrates the starting of the DPDK UIO driver.

.. code-block:: console

    Option: 12

    Unloading any existing DPDK UIO module
    Loading DPDK UIO module

The following selection demonstrates the creation of hugepages in a NUMA system.
1024 2 MByte pages are assigned to each node.
The result is that the application should use -m 4096 for starting the application to access both memory areas
(this is done automatically if the -m option is not provided).

.. note::

    If prompts are displayed to remove temporary files, type 'y'.

.. code-block:: console

    Option: 3

    Removing currently reserved hugepages
    mounting /mnt/huge and removing directory
    Input the number of 2MB pages for each node
    Example: to have 128MB of hugepages available per node,
    enter '64' to reserve 64 * 2MB pages on each node
    Number of pages for node0: 1024
    Number of pages for node1: 1024
    Reserving hugepages
    Creating /mnt/huge and mounting as hugetlbfs

The following selection demonstrates the launch of the test application to run on a single core.

.. code-block:: console

    Option: 8

    Enter hex bitmask of cores to execute test app on
    Example: to execute app on cores 0 to 7, enter 0xff
    bitmask: 0x01
    Launching app
    EAL: coremask set to 1
    EAL: Detected lcore 0 on socket 0
    ...
    EAL: Main core 0 is ready (tid=1b2ad720)
    RTE>>

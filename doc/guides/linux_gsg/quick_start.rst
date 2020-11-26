..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2010-2014 Intel Corporation.

.. _linux_setup_script:

Quick Start Setup Script
========================

The dpdk-setup.sh script, found in the usertools subdirectory, allows the user to perform the following tasks:

*   Insert and remove VFIO kernel modules

*   Remove the DPDK IGB_UIO kernel module

*   Remove the DPDK KNI kernel module

*   View network port status and reserve ports for DPDK application use

*   Set up permissions for using VFIO as a non-privileged user

Please refer to :doc:`../prog_guide/build-sdk-meson` for building DPDK.

Please refer to :doc:`../tools/hugepages` for setting up hugepages for DPDK.

Script Organization
-------------------

The dpdk-setup.sh script is logically organized into a series of steps that a user performs in sequence.
Each step provides a number of options that guide the user to completing the desired task.
The following is a brief synopsis of each step.

**Step 1: Setup Environment**

The user configures the Linux* environment to support the running of DPDK applications.
Network ports may be bound to DPDK kernel module for DPDK application use.

**Step 2: System Cleanup**

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

    [2] Display current Ethernet device settings

    [3] Bind Ethernet device to IGB UIO module

    [4] Bind Ethernet device to VFIO module

    [5] Setup VFIO permissions

    ------------------------------------------------------------------------

    Step 2: Uninstall and system cleanup

    ------------------------------------------------------------------------

    [6] Unbind NICs from IGB UIO driver

    [7] Remove IGB UIO module

    [8] Remove VFIO module

    [9] Remove KNI module

    [10] Exit Script

    Option:

The following selection demonstrates the starting of the DPDK UIO driver.

.. code-block:: console

    Option: 7

    Unloading any existing DPDK UIO module
    Loading DPDK UIO module

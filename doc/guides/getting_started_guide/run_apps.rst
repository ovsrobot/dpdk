..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2010-2025 Intel Corporation.

.. _run_apps:

Running Applications
====================

Running Applications on Linux and FreeBSD
-----------------------------------------

Compiling and Running Sample Applications
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To compile a sample application:

1. Navigate to the application's directory in the DPDK distribution.
2. Execute the ``make`` command on Linux or ``gmake`` on FreeBSD.

For instance, to compile the ``helloworld`` application:

::

    cd examples/helloworld
    make    # On Linux
    gmake   # On FreeBSD

.. note::
   If DPDK is not installed system-wide, 
   you can compile the examples as part of the DPDK build itself. 
   If DPDK is not installed system-wide, you can compile the examples as part of the DPDK build 
   itself. Use the meson build option ``-Dexamples=helloworld`` to compile specific examples 
   or ``-Dexamples=all`` to compile all examples.

To run the application, use:

::

    ./build/helloworld -l 0-2

The ``-l`` option indicates the cores on which the application should run.
This command runs the `helloworld` application on cores 0, 1, and 2.

Sample Applications Overview
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For a comprehensive list of sample applications and their guides, 
refer to the `DPDK Sample Applications User Guides <https://doc.dpdk.org/guides/sample_app_ug/index.html>`_.

EAL Parameters
--------------

Every DPDK application is linked with the DPDK target environment’s 
Environmental Abstraction Layer (EAL) library. The most essential EAL option is ``-l CORELIST``, which specifies the cores the application should run on. For example:

- ``-l 1-3`` to run on 3 cores: 1, 2, and 3.
- ``-l 8,16`` to run on 2 cores: 8 and 16.
- ``-l 1-7,9-15`` to run on 14 cores: 1 through 7 and 9 through 15.

Please refer to the `EAL parameters section <eal_parameters>` section for a more comprehensive list of options.

Running Without Root Privileges
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Refer to :ref:`running_dpdk_apps_without_root`.

Running Applications on Windows
-------------------------------

Running DPDK applications on Windows involves a few different steps. 
This guide provides detailed instructions on how to run the helloworld example
application, which can be used as a reference for running other DPDK applications.

Grant Lock Pages in Memory Privilege
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Use of hugepages ("large pages" in Windows terminology) requires
``SeLockMemoryPrivilege`` for the user running an application. 
This privilege allows the DPDK application to keep data in physical memory, 
preventing the system from paging the data to virtual memory. 
This can significantly improve the performance of your DPDK applications.

To grant this privilege:

1. Open Local Security Policy snap-in, either through Control Panel / Computer Management / Local Security Policy, or by pressing Win+R, typing ``secpol``, and pressing Enter.
2. Open Local Policies / User Rights Assignment / Lock pages in memory.
3. Add desired users or groups to the list of grantees.

The privilege is applied upon the next logon. If the privilege has been granted to the
current user, a logoff is required before it is available. 
More details can be found in the `Large-Page Support in MSDN <https://docs.microsoft.com/en-us/windows/win32/memory/large-page-support>`_.

Running the helloworld Example
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

After setting up the drivers, you can run the helloworld example to verify your setup.
Here are the steps:

1. Navigate to the examples in the build directory::

        cd C:\\Users\\me\\dpdk\\build\\examples

2. Run the helloworld application::

        dpdk-helloworld.exe -l 0-3

The output should display a hello message from each core, like this:

::

    hello from core 1
    hello from core 3
    hello from core 0
    hello from core 2

..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2015 Intel Corporation.

Compiling the Sample Applications
=================================

This section explains how to compile the DPDK sample applications.

To compile all the sample applications
--------------------------------------

Go to DPDK source:

    .. code-block:: console

        cd dpdk

Build DPDK:

   .. code-block:: console

        make defconfig
        make

Build the sample applications:

   .. code-block:: console

       make -C examples

For additional information on compiling see
:ref:`Compiling DPDK on Linux <linux_gsg_compiling_dpdk>` or
:ref:`Compiling DPDK on FreeBSD <building_from_source>`.
Applications are output to: ``dpdk/examples/app-dir/build`` or
``dpdk/examples/app-dir/{build_dir}``.


In the example above the compiled application is written to the ``build`` subdirectory.
To have the applications written to a different location,
the ``O=/path/to/build/directory`` option may be specified in the make command.

    .. code-block:: console

       make O=/tmp

To build the applications for debugging use the ``DEBUG`` option.
This option adds some extra flags, disables compiler optimizations and
sets verbose output.

    .. code-block:: console

       make DEBUG=1


To compile a single application
-------------------------------

Go to DPDK source:

    .. code-block:: console

       cd dpdk

Build DPDK:

    .. code-block:: console

        make defconfig
        make

Go to the sample application directory. Unless otherwise specified the sample
applications are located in ``dpdk/examples/``.


Build the application:

    .. code-block:: console

        make

To cross compile the sample application(s)
------------------------------------------

For cross compiling the sample application(s), please append 'CROSS=$(CROSS_COMPILER_PREFIX)' to the 'make' command.
In example of AARCH64 cross compiling:

    .. code-block:: console

        make -C examples CROSS=aarch64-linux-gnu-
               or
        make CROSS=aarch64-linux-gnu-

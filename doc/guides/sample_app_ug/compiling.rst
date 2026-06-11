..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2015 Intel Corporation.

Compiling the Sample Applications
=================================

This section explains how to compile the DPDK sample applications.
Sample applications are located in ``dpdk/examples/``.

To Compile All the Sample Applications
---------------------------------------

Set up the build directory (if not already done):

.. code-block:: console

   cd dpdk
   meson setup build

.. note::

   The build directory name (``build`` in this example) can be chosen freely.
   Replace ``<build_dir>`` in subsequent commands with your chosen directory name.

Go to the build directory:

.. code-block:: console

   cd build

.. code-block:: console

   meson configure -Dexamples=all

Compile:

.. code-block:: console

   ninja

For additional information on compiling see
:ref:`Compiling DPDK on Linux <linux_gsg_compiling_dpdk>` or
:ref:`Compiling DPDK on FreeBSD <building_from_source>`.

Compiled applications are output to ``dpdk/<build_dir>/examples``.


To Compile a Single Application
--------------------------------

A single application can be compiled using meson during the DPDK build,
or standalone using make with an installed DPDK.

Using meson
~~~~~~~~~~~

Go to the build directory (after ``meson setup`` as shown above):

.. code-block:: console

   cd dpdk/build

Enable example app compilation:

.. code-block:: console

   meson configure -Dexamples=helloworld

Compile:

.. code-block:: console

   ninja


Using make (standalone)
~~~~~~~~~~~~~~~~~~~~~~~

To compile a sample application standalone using make, DPDK must first
be installed on the system and pkg-config must be configured.
See :ref:`building_app_using_installed_dpdk` for installation instructions.

Go to the sample application directory:

.. code-block:: console

   cd dpdk/examples/helloworld

Build the application:

.. code-block:: console

   make

To build the application for debugging use the ``DEBUG`` option.
This option adds some extra flags, disables compiler optimizations and
sets verbose output:

.. code-block:: console

   make DEBUG=1

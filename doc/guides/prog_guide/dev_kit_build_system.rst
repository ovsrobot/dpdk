..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2010-2014 Intel Corporation.

.. _Development_Kit_Build_System:

Development Kit Build System
============================

The DPDK requires a build system for compilation activities and so on.
This section describes the constraints and the mechanisms used in the DPDK framework.

There are two use-cases for the framework:

*   Compilation of the DPDK libraries and sample applications;
    the framework generates specific binary libraries,
    include files and sample applications

*   Compilation of an external application or library, using an installed binary DPDK

Building the Development Kit Binary
-----------------------------------

The following provides details on how to build the DPDK binary.

Build Directory Concept
~~~~~~~~~~~~~~~~~~~~~~~

After installation, a build directory structure is created.
Each build directory contains include files, libraries, and applications.

A build directory is specific to a configuration that includes architecture + execution environment + toolchain.
It is possible to have several build directories sharing the same sources with different configurations.


Building External Applications
------------------------------

Since DPDK is in essence a development kit, the first objective of end users will be to create an application using this SDK.

For a new application, the user must create their own Makefile. This is described in
:ref:`Building Your Own Application <Building_Your_Own_Application>`.

Depending on the chosen target (architecture, machine, executive environment, toolchain) defined, the applications and
libraries will compile using the appropriate .h files and will link with the appropriate .a files.

To compile their application, the user just has to call make.
The compilation result will be located in /path/to/my_app/build directory.

Sample applications are provided in the examples directory.

.. _Makefile_Description:

Makefile Description
--------------------

General Rules For DPDK Makefiles
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In the DPDK, Makefiles always define specific variables for RTE build system.

   The following is a very simple example of an external application Makefile:

   ..  code-block:: make

        # binary name
        APP = helloworld

        # all source are stored in SRCS-y
        SRCS-y := main.c


.. _Internally_Generated_Build_Tools:

Internally Generated Build Tools
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``app/dpdk-pmdinfogen``


``dpdk-pmdinfogen`` scans an object (.o) file for various well known symbol names.
These well known symbol names are defined by various macros and used to export
important information about hardware support and usage for pmd files.  For
instance the macro:

.. code-block:: c

   RTE_PMD_REGISTER_PCI(name, drv)

Creates the following symbol:

.. code-block:: c

   static char this_pmd_name0[] __attribute__((used)) = "<name>";


Which ``dpdk-pmdinfogen`` scans for.  Using this information other relevant
bits of data can be exported from the object file and used to produce a
hardware support description, that ``dpdk-pmdinfogen`` then encodes into a
JSON formatted string in the following format:

.. code-block:: c

   static char <name_pmd_string>="PMD_INFO_STRING=\"{'name' : '<name>', ...}\"";


These strings can then be searched for by external tools to determine the
hardware support of a given library or application.


.. _Useful_Variables_Provided_by_the_Build_System:

Useful Variables Provided by the Build System
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

*   RTE_ARCH: Defines the architecture (i686, x86_64).

*   RTE_MACHINE: Defines the machine.

*   RTE_TOOLCHAIN: Defines the toolchain (gcc , icc).

*   RTE_EXEC_ENV: Defines the executive environment (linux).

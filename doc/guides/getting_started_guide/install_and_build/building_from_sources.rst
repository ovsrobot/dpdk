..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2010-2025 Intel Corporation.

.. _building_from_sources:

Building and Installing DPDK from Sources
=========================================

This chapter provides a comprehensive guide for building DPDK from sources.
It covers the necessary steps, prerequisites, and considerations for different architectures and compilers.

Required Tools
--------------

To build DPDK, you'll need the following tools:

- A C compiler like ``gcc`` (version 5+) or ``clang`` (version 3.6+)
- ``pkg-config`` or ``pkgconf``
- Python 3.6 or later
- ``meson`` (version 0.57.0) and ``ninja``
- ``pyelftools`` (version 0.22+)

Platform-Specific Tool Installation
-----------------------------------

Linux
^^^^^

Alpine
""""""

.. code-block:: bash

   sudo apk add alpine-sdk bsd-compat-headers gcc pkg-config python3 meson ninja pyelftools numactl-dev

Debian, Ubuntu, and derivatives
"""""""""""""""""""""""""""""""

.. code-block:: bash

   sudo apt install build-essential gcc pkg-config python3 meson ninja pyelftools libnuma-dev

Fedora and RedHat Enterprise Linux (RHEL)
"""""""""""""""""""""""""""""""""""""""""

.. code-block:: bash

   sudo dnf groupinstall "Development Tools"
   sudo dnf install gcc pkg-config python3 meson ninja python3-pyelftools numactl-devel

openSUSE
""""""""

.. code-block:: bash

   sudo zypper install -t pattern devel_basis
   sudo zypper install gcc pkg-config python3 meson ninja python3-pyelftools libnuma-devel

FreeBSD
^^^^^^^

.. code-block:: bash

   pkg install pkgconf python3 meson ninja pyelftools

.. note::

   If you're using FreeBSD, make sure kernel sources are included during the FreeBSD installation.

Windows System Requirements
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Building the DPDK and its applications on Windows requires one of the following
environments:

- The Clang-LLVM C compiler and Microsoft MSVC linker.
- The MinGW-w64 toolchain (either native or cross).

The Meson Build system is used to prepare the sources for compilation with the Ninja backend.

.. _clang_llvm:

Option 1: Clang-LLVM C Compiler and Microsoft MSVC Linker
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""

1. Install the Compiler: Download and install the Clang compiler from the 
   `LLVM website <http://releases.llvm.org/>`_.

2. Install the Linker: Download and install the Build Tools for Visual Studio from the
   `Microsoft website <https://visualstudio.microsoft.com/downloads/>`_.
   When installing build tools, select the “Visual C++ build tools” option and make sure
   the Windows SDK is selected.

.. _mingw_w64_toolchain:

Option 2: MinGW-w64 Toolchain
""""""""""""""""""""""""""""""

1. On Linux (for cross-compilation): Install MinGW-w64 via a package manager. 
   Version 4.0.4 for Ubuntu 16.04 cannot be used due to a MinGW-w64 bug.

2. On Windows: Obtain the latest version installer from the
   `MinGW-w64 repository <https://mingw-w64.org/doku.php>`_. 
   Any thread model (POSIX or Win32) can be chosen, DPDK does not rely on it. 
   Install to a folder without spaces in its name, like ``C:\MinGW``. 
   This path is assumed for the rest of this guide.

Install the Build System
^^^^^^^^^^^^^^^^^^^^^^^^

Download and install the build system from the
`Meson website <http://mesonbuild.com/Getting-meson.html#installing-meson-and-ninja-with-the-msi-installer>`_.
A good option to choose is the MSI installer for both meson and ninja together.
Required version is Meson 0.57.x (baseline).

Getting the DPDK Source
-----------------------

Linux and FreeBSD
^^^^^^^^^^^^^^^^^

.. code-block:: bash

   wget https://fast.dpdk.org/rel/dpdk-20.11.tar.xz
   tar -xJf dpdk-20.11.tar.xz
   cd dpdk-20.11

Windows
^^^^^^^

Download the DPDK source code from `DPDK's official website <https://www.dpdk.org/>`_ or clone the repository using a Git client. Extract the downloaded archive, if applicable, and navigate to the DPDK directory.

Navigate to the directory where the DPDK source code is located:

.. code-block:: bash

   cd C:\path\to\dpdk-20.11

Building DPDK
-------------

.. note::

   In all examples below, "build" is used as the name of the build directory. It is not part of the command itself.

Linux and FreeBSD
^^^^^^^^^^^^^^^^^

.. code-block:: bash

   meson setup build
   meson compile -C build

Windows
^^^^^^^

**Option 1: Using Clang-LLVM**

.. code-block:: bash

   set CC=clang
   meson setup -Dexamples=helloworld build
   meson compile -C build

**Option 2: Using MinGW-w64**

.. code-block:: bash

   set PATH=C:\MinGW\mingw64\bin;%PATH%
   meson setup -Dexamples=helloworld build
   meson compile -C build

.. note::

   For detailed information on Meson build configuration options specific to DPDK, see :ref:`DPDK Meson Build Configuration Options <dpdk_meson_build_options>`.

Cross-Compilation Instructions for Different Architectures
----------------------------------------------------------

For instructions on building DPDK for ARM64, LoongArch, and RISC-V, refer to :ref:`cross_compile_dpdk`.

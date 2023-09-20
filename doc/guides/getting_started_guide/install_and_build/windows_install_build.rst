..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2010-2015 Intel Corporation.

.. _windows_install_build:

Windows DPDK Build
==================

Before you begin the process of building DPDK on Windows, 
make sure your system meets all the necessary requirements as outlined below.

Windows System Requirements
---------------------------

Building the DPDK and its applications on Windows requires one of the following
environments:

- The Clang-LLVM C compiler and Microsoft MSVC linker.
- The MinGW-w64 toolchain (either native or cross).

The Meson Build system is used to prepare the sources for compilation with the Ninja backend.

Option 1: Clang-LLVM C Compiler and Microsoft MSVC Linker
---------------------------------------------------------

1. Install the Compiler: Download and install the clang compiler from the 
`LLVM website <http://releases.llvm.org/>`_.

2. Install the Linker: Download and install the Build Tools for Visual Studio from the
`Microsoft website <https://visualstudio.microsoft.com/downloads/>`_. 
When installing build tools, select the “Visual C++ build tools” option and make sure
the Windows SDK is selected.

Option 2: MinGW-w64 Toolchain
-----------------------------

1. On Linux (for cross-compilation): Install MinGW-w64 via a package manager. 
Version 4.0.4 for Ubuntu 16.04 cannot be used due to a MinGW-w64 bug.

2. On Windows: Obtain the latest version installer from the
`MinGW-w64 repository <https://mingw-w64.org/doku.php>`_. 
Any thread model (POSIX or Win32) can be chosen, DPDK does not rely on it. 
Install to a folder without spaces in its name, like ``C:\MinGW``. 
This path is assumed for the rest of this guide.

Install the Build System
------------------------

Download and install the build system from the
`Meson website <http://mesonbuild.com/Getting-meson.html#installing-meson-and-ninja-with-the-msi-installer>`_. 
A good option to choose is the MSI installer for both meson and ninja together.
Recommended version is either Meson 0.57.0 (baseline) or the latest release.

Install the Backend
-------------------

If using Ninja, download and install the backend from the
`Ninja website <https://ninja-build.org/>`_ or install along with the meson build
system. 

Once you have verified that your system meets these requirements, 
you can proceed with the following steps to build DPDK.

Build the Code
--------------

The build environment is setup to build the EAL and the helloworld example by default.
To compile the examples, the flag -Dexamples is required.

**Option 1. Native Build on Windows**

When using Clang-LLVM, specifying the compiler might be required to complete the meson
command::

        set CC=clang

When using MinGW-w64, it is sufficient to have toolchain executables in PATH::

        set PATH=C:\MinGW\mingw64\bin;%PATH%

To compile the examples::

        cd C:\Users\me\dpdk
        meson -Dexamples=helloworld build
        ninja -C build

**Option 2. Cross-Compile with MinGW-w64**

The cross-file option must be specified for Meson. 
Depending on the distribution, paths in this file may need adjustments::

        meson --cross-file config/x86/cross-mingw -Dexamples=helloworld build
        ninja -C build
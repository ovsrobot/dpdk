..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2022 Loongson Technology Corporation Limited

Cross compiling DPDK for LoongArch
==================================

This chapter describes how to cross compile DPDK for LoongArch from x86 build
hosts.

.. note::

    Due to some of the code under review, the current Linux 5.19 cannot boot
    on LoongArch system. There are still some Linux distributions that have
    supported LoongArch host, such as Anolis OS, Kylin, Loongnix and UOS. These
    distributions base on Linux kernel 4.19 supported by Loongson Corporation.
    Because LoongArch is such a new platform with many fundamental pieces of
    software still under development, it is currently recommended to cross
    compile DPDK on x86 for LoongArch.


Prerequisites
-------------

Ensure that you have all pre-requisites for building DPDK natively as those
will be required also for cross-compilation.

Linux kernel
~~~~~~~~~~~~

Make sure that LoongArch host is running Linux kernel 4.19 or newer supported
by Loongson Corporation. The support for LoongArch in the current Linux 5.19
is not complete because it still misses some patches to add for other
subsystems.

GNU toolchain
-------------

Obtain the cross toolchain
~~~~~~~~~~~~~~~~~~~~~~~~~~

The build process was tested using:

* Latest `LoongArch GNU toolchain
  <https://github.com/loongson/build-tools/releases/download/2022.08.11/loongarch64-clfs-5.1-cross-tools-gcc-glibc.tar.xz>`_
  on Debian 10.4 or CentOS 8.

Alternatively the toolchain may be built straight from the source via CLFS, to
do that follow the instructions on `CLFS for LoongArch64
<https://github.com/sunhaiyong1978/CLFS-for-LoongArch>`_ github page.

To download cross tools from github we can use the following command:

.. code-block:: console

   wget -P /tmp/ https://github.com/loongson/build-tools/releases/download/2022.08.11/loongarch64-clfs-5.1-cross-tools-gcc-glibc.tar.xz

Unzip and add into the PATH
~~~~~~~~~~~~~~~~~~~~~~~~~~~

After downloading the cross-tools file, we need unzip and add those executable
binaries into the PATH as follows:

.. code-block:: console

   tar -xvf /tmp/loongarch64-clfs-5.1-cross-tools-gcc-glibc.tar.xz -C <cross_tool_install_dir> --strip-components 1
   export PATH=$PATH:<cross_tool_install_dir>/bin


Cross Compiling DPDK with GNU toolchain using Meson
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To cross-compile DPDK for generic LoongArch we can use the following command:

.. code-block:: console

   meson cross-build --cross-file config/loongarch/loongarch_loongarch64_linux_gcc
   ninja -C cross-build

Supported cross-compilation targets
-----------------------------------

Currently the following target is supported:

* Generic LoongArch64 ISA: ``config/loongarch/loongarch_loongarch64_linux_gcc``

To add a new target support, a corresponding cross-file has to be added to
``config/loongarch`` directory.

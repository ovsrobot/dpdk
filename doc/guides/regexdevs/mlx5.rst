..  SPDX-License-Identifier: BSD-3-Clause
   Copyright 2020 Mellanox Technologies, Ltd

.. include:: <isonum.txt>

MLX5 RegEx driver
=================

The MLX5 RegEx (Regular Expression) driver library
(**librte_pmd_mlx5_regex**) provides support for **Mellanox BlueField 2**
families of 25/50/100/200 Gb/s adapters.

.. note::

   Due to external dependencies, this driver is disabled in default
   configuration of the "make" build. It can be enabled with
   ``CONFIG_RTE_LIBRTE_MLX5_REGEX_PMD=y`` or by using "meson" build system which
   will detect dependencies.


Design
------

This PMD is configuring the RegEx HW engine.
For the PMD to work, the application must supply
a precompiled rule file in rof2 format.

The PMD uses libibverbs and libmlx5 to access the device firmware
or directly the hardware components.
There are different levels of objects and bypassing abilities
to get the best performances:

- Verbs is a complete high-level generic API
- Direct Verbs is a device-specific API
- DevX allows to access firmware objects

Enabling librte_pmd_mlx5_regex causes DPDK applications to be linked against
libibverbs.

A Mellanox mlx5 PCI device can be probed by either net/mlx5 driver or regex/mlx5
driver but not in parallel. Hence, the user should decide the driver by disabling
the net device using ``CONFIG_RTE_LIBRTE_MLX5_PMD``. when using the make build system
or ``disable_drivers`` option when using the meson build with ``net/mlx5,vdpa/mlx5``

Supported NICs
--------------

* Mellanox\ |reg| BlueField 2 SmartNIC

Prerequisites
-------------

- BlueField 2 running Mellonx supported kernel.
- Enable the RegEx caps using system call from the BlueField 2.
- Official support is not yet released.

Compilation options
~~~~~~~~~~~~~~~~~~~

These options can be modified in the ``.config`` file.

- ``CONFIG_RTE_LIBRTE_MLX5_REGEX_PMD`` (default **n**)

  Toggle compilation of librte_pmd_mlx5 itself.


Run-time configuration
~~~~~~~~~~~~~~~~~~~~~~

- **ethtool** operations on related kernel interfaces also affect the PMD.

..  SPDX-License-Identifier: BSD-3-Clause
    Copyright 2024 ZTE Corporation

ZXDH Rawdev Driver
======================

The ``zxdh`` rawdev driver is an implementation of the rawdev API,
that provides communication between two separate hosts.
This is achieved via using the GDMA controller of Dinghai SoC,
which can be configured through exposed MPF devices.

Device Setup
-------------

It is recommended to bind the ZXDH MPF kernel driver for MPF devices (Not mandatory).
The kernel drivers can be downloaded at `ZTE Official Website
<https://enterprise.zte.com.cn/>`_.

Initialization
--------------

The ``zxdh`` rawdev driver needs to work in IOVA PA mode.
Consider using ``--iova-mode=pa`` in the EAL options.

Platform Requirement
~~~~~~~~~~~~~~~~~~~~

This PMD is only supported on ZTE Neo Platforms:
- Neo X510/X512


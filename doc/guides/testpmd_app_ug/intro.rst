..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2010-2014 Intel Corporation.

Introduction
============

This document is a user guide for the ``testpmd`` example application that is shipped as part of the Data Plane Development Kit.

``testpmd`` is a tool to test ethdev NIC features, including NIC
hardware features such as Flow Director.  It receives packets on each
configured port and forwards them.  By default, packets received on
port 0 are forwarded to port 1, and vice versa, and similarly for
ports 2 and 3, ports 4 and 5, and so on.  If an odd number of ports is
configured, packets received on the last port are sent back out on the
same port.

The guide shows how to build and run the testpmd application and
how to configure the application from the command line and the run-time environment.

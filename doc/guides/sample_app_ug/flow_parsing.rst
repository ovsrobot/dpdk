..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2026 DynaNIC Semiconductors, Ltd.

Flow Parsing Sample Application
================================

Overview
--------

The flow parsing sample application demonstrates how to use the ethdev flow
parser library to convert testpmd-style flow rule strings into ``rte_flow`` C
structures without requiring EAL initialization.


Compiling the Application
-------------------------

To compile the sample application, see :doc:`compiling`.

The application is located in the ``flow_parsing`` sub-directory.


Running the Application
-----------------------

Since this example does not use EAL, it can be run directly:

.. code-block:: console

   ./build/examples/dpdk-flow_parsing

The application prints parsed attributes, patterns, and actions for several
example flow rule strings.


Example Output
--------------

.. code-block:: none

   === Parsing Flow Attributes ===
   Input: "ingress"
     Attributes:
       group=0 priority=0
       ingress=1 egress=0 transfer=0

   === Parsing Flow Patterns ===
   Input: "eth / ipv4 src is 192.168.1.1 / end"
     Pattern (3 items):
       [0] ETH (any)
       [1] IPV4 src=192.168.1.1 dst=0.0.0.0
       [2] END

   === Parsing Flow Actions ===
   Input: "mark id 100 / count / queue index 5 / end"
     Actions (4 items):
       [0] MARK id=100
       [1] COUNT
       [2] QUEUE index=5
       [3] END

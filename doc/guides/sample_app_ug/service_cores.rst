..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2017 Intel Corporation.

Service Cores Sample Application
================================

Overview
--------

This sample application demonstrates the service cores API of DPDK.
The service cores infrastructure is part of the DPDK EAL and allows any
DPDK component to register a service. A service is a work item or task that
requires CPU time to perform its duty.

This sample application registers 5 dummy services to demonstrate how the
service cores API can orchestrate these services to run on different service
lcores. The orchestration is performed by calling the service cores APIs.
The sample application introduces a "profile" concept to group service-to-core
mapping configurations. Note that profiles are application-specific and not
part of the service cores API itself.


Compiling the Application
-------------------------

See :doc:`compiling`.

The application is located in the ``service_cores`` sub-directory.

Running the Application
-----------------------

To run the example, execute the binary. Since the application dynamically
adds service cores at runtime, there is no requirement to
pass a service core-mask as an EAL argument at startup time.

.. code-block:: console

    $ ./<build_dir>/examples/dpdk-service_cores


Explanation
-----------

The following sections explain the application code, focusing on registering
services from an application's perspective and modifying service core counts
and mappings at runtime.


Registering a Service
~~~~~~~~~~~~~~~~~~~~~

The following code section shows how to register a service as an application.
Note: The service component header must be included by the application in
order to register services: ``rte_service_component.h``. In addition, the
service cores header ``rte_service.h`` provides the runtime functions to add,
remove, and remap service cores.

.. literalinclude:: ../../../examples/service_cores/main.c
    :language: c
    :start-after: Register a service as an application. 8<
    :end-before: >8 End of registering a service as an application.
    :dedent: 2


Controlling A Service Core
~~~~~~~~~~~~~~~~~~~~~~~~~~

This section demonstrates how to add a service core and assign a service to it.
The ``rte_service.h`` header file provides functions for dynamically adding
and removing cores. These APIs use lcore IDs similar to existing DPDK
functions.

These are the functions to start a service core, and have it run a service:

.. literalinclude:: ../../../examples/service_cores/main.c
    :language: c
    :start-after: Register a service as an application. 8<
    :end-before: >8 End of registering a service as an application.
    :dedent: 2

Removing A Service Core
~~~~~~~~~~~~~~~~~~~~~~~

To remove a service core, perform the adding steps in reverse order.
Note: Removing a service core is not allowed if a service is running and
the service core is the only core running that service (see documentation
for ``rte_service_lcore_stop`` function for details).


Conclusion
~~~~~~~~~~

The service cores infrastructure provides DPDK with two main features.

First, it abstracts hardware differences: service cores can provide CPU cycles
to software fallback implementations, allowing applications to be abstracted
from hardware and software availability differences.

Second, it provides a flexible method for registering functions to run,
allowing function execution to scale across multiple CPUs.

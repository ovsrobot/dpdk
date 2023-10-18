..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2023 Marvell.

dpdk-graph Application
======================

The ``dpdk-graph`` tool is a Data Plane Development Kit (DPDK)
application that allows exercising various graph use cases.
This application has a generic framework to add new graph based use cases to
verify functionality. Each use case is defined as a ``<usecase>.cli`` file.
Based on the input file, application creates a graph to cater the use case.

Also this application framework can be used by other graph based applications.

Running the Application
-----------------------

The application has a number of command line options which can be provided in
following syntax

.. code-block:: console

   dpdk-graph [EAL Options] -- [application options]

EAL Options
~~~~~~~~~~~

Following are the EAL command-line options that can be used in conjunction
with the ``dpdk-graph`` application.
See the DPDK Getting Started Guides for more information on these options.

*   ``-c <COREMASK>`` or ``-l <CORELIST>``

        Set the hexadecimal bit mask of the cores to run on. The CORELIST is a
        list of cores to be used.

Application Options
~~~~~~~~~~~~~~~~~~~

Following are the application command-line options:

* ``-h``

        Set the host IPv4 address over which telnet session can be opened.
        It is an optional parameter. Default host address is 0.0.0.0.

* ``-p``

        Set the L4 port number over which telnet session can be opened.
	It is an optional parameter. Default port is 8086.

* ``-s``

        Script name with absolute path which specifies the use case. It is
        a mandatory parameter which will be used to create desired graph
        for a given use case.

* ``--help``

       Dumps application usage

Supported CLI commands
----------------------

This section provides details on commands which can be used in ``<usecase>.cli``
file to express the requested use case configuration.

.. list-table:: Exposed CLIs
   :widths: 40 40 10 10
   :header-rows: 1
   :class: longtable

   * - Command
     - Description
     - Dynamic
     - Optional
   * - Dummy command
     - Dummy command description
     - No
     - No
   * - mempool <mempool_name> size <mbuf_size> buffers <number_of_buffers> cache <cache_size> numa <numa_id>
     - Command to create mempool which will be further associated to RxQ to dequeue the packets
     - No
     - No
   * - help mempool
     - Command to dump mempool help message
     - Yes
     - Yes

Runtime configuration
---------------------

Application allows some configuration to be modified at runtime using a telnet session.
Application initiates a telnet server with host address ``0.0.0.0`` and port number ``8086``
by default.

if user passes ``-h`` and ``-p`` options while running application then corresponding
IP address and port number will be used for telnet session.

After successful launch of application, client can connect to application using given
host & port and console will be accessed with prompt ``graph>``.

Command to access a telnet session

.. code-block:: console

   telnet <host> <port>

Example: ``dpdk-graph`` is started with -h 10.28.35.207 and -p 50000 then

.. code-block:: console

   $ telnet 10.28.35.207 50000
   Trying 10.28.35.207...
   Connected to 10.28.35.207.
   Escape character is '^]'.

   Welcome!

   graph>
   graph>
Created graph for use case
--------------------------

On the successful execution of ``<usecase>.cli`` file, corresponding graph will be created.
This section mentions the created graph for each use case.

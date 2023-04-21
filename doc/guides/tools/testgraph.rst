..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(C) 2023 Marvell International Ltd.

dpdk-test-graph Application
===========================

The ``dpdk-test-graph`` tool is a Data Plane Development Kit (DPDK) application that allows
exercising various graph library features. This application has a generic framework to add
new test configurations and expand test coverage to verify the functionality of graph nodes
and observe the graph cluster statistics.

Running the Application
-----------------------

The application has a number of command line options:

.. code-block:: console

   dpdk-test-eventdev [EAL Options] -- [application options]

EAL Options
~~~~~~~~~~~

The following are the EAL command-line options that can be used in conjunction
with the ``dpdk-test-graph`` application.
See the DPDK Getting Started Guides for more information on these options.

*   ``-c <COREMASK>`` or ``-l <CORELIST>``

        Set the hexadecimal bitmask of the cores to run on. The corelist is a
        list of cores to use.

Application Options
~~~~~~~~~~~~~~~~~~~

The following are the application command-line options:

* ``-p <n>``

        Set the ethdev port mask.

* ``-P``

        Set the ethdev ports in promiscuous mode.

* ``--config <config>``

        Set the Rxq configuration.
        (i.e. ``--config (port_id,rxq,lcore_id)[,(port_id,rxq,lcore_id)]``).

* ``--node-pattern <n>``

        Set the node patterns to use in graph creation.
        (i.e. ``--node-pattern (node_name0,node_name1[,node_nameX])``).

* ``--per-port-pool``

        Use separate buffer pool per port.

* ``--no-numa``

        Disable numa awareness.

* ``--interactive``

        Switch to interactive mode.

Running the Tool
~~~~~~~~~~~~~~~~

Here is the sample command line to run simple iofwd test::

       ./dpdk-test-graph -a 0002:03:00.0 -a 0002:04:00.0 -c 0xF  -- -p 0x3 -P  \
       --config "(0,0,2),(1,0,2)" --node-pattern "(ethdev_rx,ethdev_tx)"

Below is a sample command line to punt rx packets to kernel::

       ./dpdk-test-graph -a 0002:03:00.0 -a 0002:04:00.0 -c 0xF  -- -p 0x3 -P  \
       --config "(0,0,2),(1,0,2)" --node-pattern "(ethdev_rx,punt_kernel)"

Interactive mode
~~~~~~~~~~~~~~~~

Tool uses ``--interactive`` command line option to enter interactive mode and use cmdline options
to setup the required node configurations, create graph and than start graph_walk.


testgraph> help

Help is available for the following sections:

    help control                    : Start and stop graph walk.
    help display                    : Displaying port, stats and config information.
    help config                     : Configuration information.
    help all                        : All of the above sections.

testgraph> help all

Control forwarding:

start graph_walk
 Start graph_walk on worker threads.

stop graph_walk
 Stop worker threads from running graph_walk.

quit
 Quit to prompt.


Display:

show node_list
 Display the list of supported nodes.

show graph_stats
 Display the node statistics of graph cluster.


Configuration:

set lcore_config (port_id0,rxq0,lcore_idX),........,(port_idX,rxqX,lcoreidY)
 Set lcore configuration.

create_graph (node0_name,node1_name,...,nodeX_name)
 Create graph instances using the provided node details.

destroy_graph
 Destroy the graph instances.

testgraph>

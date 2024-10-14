..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(C) 2020 Marvell International Ltd.

Graph Library and Inbuilt Nodes
===============================

Graph architecture abstracts the data processing functions as a ``node`` and
``links`` them together to create a complex ``graph`` to enable reusable/modular
data processing functions.

The graph library provides API to enable graph framework operations such as
create, lookup, dump and destroy on graph and node operations such as clone,
edge update, and edge shrink, etc. The API also allows to create the stats
cluster to monitor per graph and per node stats.

Features
--------

Features of the Graph library are:

- Nodes as plugins.
- Support for out of tree nodes.
- Inbuilt nodes for packet processing.
- Multi-process support.
- Low overhead graph walk and node enqueue.
- Low overhead statistics collection infrastructure.
- Support to export the graph as a Graphviz dot file. See ``rte_graph_export()``.
- Allow having another graph walk implementation in the future by segregating
  the fast path(``rte_graph_worker.h``) and slow path code.

Advantages of Graph architecture
--------------------------------

- Memory latency is the enemy for high-speed packet processing, moving the
  similar packet processing code to a node will reduce the I cache and D
  caches misses.
- Exploits the probability that most packets will follow the same nodes in the
  graph.
- Allow SIMD instructions for packet processing of the node.-
- The modular scheme allows having reusable nodes for the consumers.
- The modular scheme allows us to abstract the vendor HW specific
  optimizations as a node.

Performance tuning parameters
-----------------------------

- Test with various burst size values (256, 128, 64, 32) using
  RTE_GRAPH_BURST_SIZE config option.
  The testing shows, on x86 and arm64 servers, The sweet spot is 256 burst
  size. While on arm64 embedded SoCs, it is either 64 or 128.
- Disable node statistics (using ``RTE_LIBRTE_GRAPH_STATS`` config option)
  if not needed.

Programming model
-----------------

Anatomy of Node:
~~~~~~~~~~~~~~~~

.. _figure_anatomy_of_a_node:

.. figure:: img/anatomy_of_a_node.*

   Anatomy of a node

The node is the basic building block of the graph framework.

A node consists of:

process():
^^^^^^^^^^

The callback function will be invoked by worker thread using
``rte_graph_walk()`` function when there is data to be processed by the node.
A graph node process the function using ``process()`` and enqueue to next
downstream node using ``rte_node_enqueue*()`` function.

Context memory:
^^^^^^^^^^^^^^^

It is memory allocated by the library to store the node-specific context
information. This memory will be used by process(), init(), fini() callbacks.

init():
^^^^^^^

The callback function will be invoked by ``rte_graph_create()`` on when
a node gets attached to a graph.

fini():
^^^^^^^

The callback function will be invoked by ``rte_graph_destroy()`` on when a
node gets detached to a graph.

Node name:
^^^^^^^^^^

It is the name of the node. When a node registers to graph library, the library
gives the ID as ``rte_node_t`` type. Both ID or Name shall be used lookup the
node. ``rte_node_from_name()``, ``rte_node_id_to_name()`` are the node
lookup functions.

nb_edges:
^^^^^^^^^

The number of downstream nodes connected to this node. The ``next_nodes[]``
stores the downstream nodes objects. ``rte_node_edge_update()`` and
``rte_node_edge_shrink()`` functions shall be used to update the ``next_node[]``
objects. Consumers of the node APIs are free to update the ``next_node[]``
objects till ``rte_graph_create()`` invoked.

next_node[]:
^^^^^^^^^^^^

The dynamic array to store the downstream nodes connected to this node. Downstream
node should not be current node itself or a source node.

Source node:
^^^^^^^^^^^^

Source nodes are static nodes created using ``RTE_NODE_REGISTER`` by passing
``flags`` as ``RTE_NODE_SOURCE_F``.
While performing the graph walk, the ``process()`` function of all the source
nodes will be called first. So that these nodes can be used as input nodes for a graph.

Node creation and registration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
* Node implementer creates the node by implementing ops and attributes of
  ``struct rte_node_register``.

* The library registers the node by invoking RTE_NODE_REGISTER on library load
  using the constructor scheme. The constructor scheme used here to support multi-process.

Link the Nodes to create the graph topology
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. _figure_link_the_nodes:

.. figure:: img/link_the_nodes.*

   Topology after linking the nodes

Once nodes are available to the program, Application or node public API
functions can links them together to create a complex packet processing graph.

There are multiple different types of strategies to link the nodes.

Method (a):
^^^^^^^^^^^
Provide the ``next_nodes[]`` at the node registration time. See  ``struct rte_node_register::nb_edges``.
This is a use case to address the static node scheme where one knows upfront the
``next_nodes[]`` of the node.

Method (b):
^^^^^^^^^^^
Use ``rte_node_edge_get()``, ``rte_node_edge_update()``, ``rte_node_edge_shrink()``
to update the ``next_nodes[]`` links for the node runtime but before graph create.

Method (c):
^^^^^^^^^^^
Use ``rte_node_clone()`` to clone a already existing node, created using RTE_NODE_REGISTER.
When ``rte_node_clone()`` invoked, The library, would clone all the attributes
of the node and creates a new one. The name for cloned node shall be
``"parent_node_name-user_provided_name"``.

This method enables the use case of Rx and Tx nodes where multiple of those nodes
need to be cloned based on the number of CPU available in the system.
The cloned nodes will be identical, except the ``"context memory"``.
Context memory will have information of port, queue pair in case of Rx and Tx
ethdev nodes.

Create the graph object
~~~~~~~~~~~~~~~~~~~~~~~
Now that the nodes are linked, Its time to create a graph by including
the required nodes. The application can provide a set of node patterns to
form a graph object. The ``fnmatch()`` API used underneath for the pattern
matching to include the required nodes. After the graph create any changes to
nodes or graph is not allowed.

The ``rte_graph_create()`` API shall be used to create the graph.

Example of a graph object creation:

.. code-block:: console

   {"ethdev_rx-0-0", ip4*, ethdev_tx-*"}

In the above example, A graph object will be created with ethdev Rx
node of port 0 and queue 0, all ipv4* nodes in the system,
and ethdev tx node of all ports.

Graph models
~~~~~~~~~~~~
There are two different kinds of graph walking models. User can select the model using
``rte_graph_worker_model_set()`` API. If the application decides to use only one model,
the fast path check can be avoided by defining the model with RTE_GRAPH_MODEL_SELECT.
For example:

.. code-block:: c

  #define RTE_GRAPH_MODEL_SELECT RTE_GRAPH_MODEL_RTC
  #include "rte_graph_worker.h"

RTC (Run-To-Completion)
^^^^^^^^^^^^^^^^^^^^^^^
This is the default graph walking model. Specifically, ``rte_graph_walk_rtc()`` and
``rte_node_enqueue*`` fast path API functions are designed to work on single-core to
have better performance. The fast path API works on graph object, So the multi-core
graph processing strategy would be to create graph object PER WORKER.

Example:

Graph: node-0 -> node-1 -> node-2 @Core0.

.. code-block:: diff

    + - - - - - - - - - - - - - - - - - - - - - +
    '                  Core #0                  '
    '                                           '
    ' +--------+     +---------+     +--------+ '
    ' | Node-0 | --> | Node-1  | --> | Node-2 | '
    ' +--------+     +---------+     +--------+ '
    '                                           '
    + - - - - - - - - - - - - - - - - - - - - - +

Dispatch model
^^^^^^^^^^^^^^
The dispatch model enables a cross-core dispatching mechanism which employs
a scheduling work-queue to dispatch streams to other worker cores which
being associated with the destination node.

Use ``rte_graph_model_mcore_dispatch_lcore_affinity_set()`` to set lcore affinity
with the node.
Each worker core will have a graph repetition. Use ``rte_graph_clone()`` to clone
graph for each worker and use``rte_graph_model_mcore_dispatch_core_bind()`` to
bind graph with the worker core.

Example:

Graph topo: node-0 -> Core1; node-1 -> node-2; node-2 -> node-3.
Config graph: node-0 @Core0; node-1/3 @Core1; node-2 @Core2.

.. code-block:: diff

    + - - - - - -+     +- - - - - - - - - - - - - +     + - - - - - -+
    '  Core #0   '     '          Core #1         '     '  Core #2   '
    '            '     '                          '     '            '
    ' +--------+ '     ' +--------+    +--------+ '     ' +--------+ '
    ' | Node-0 | - - - ->| Node-1 |    | Node-3 |<- - - - | Node-2 | '
    ' +--------+ '     ' +--------+    +--------+ '     ' +--------+ '
    '            '     '     |                    '     '      ^     '
    + - - - - - -+     +- - -|- - - - - - - - - - +     + - - -|- - -+
                             |                                 |
                             + - - - - - - - - - - - - - - - - +


In fast path
~~~~~~~~~~~~
Typical fast-path code looks like below, where the application
gets the fast-path graph object using ``rte_graph_lookup()``
on the worker thread and run the ``rte_graph_walk()`` in a tight loop.

.. code-block:: c

    struct rte_graph *graph = rte_graph_lookup("worker0");

    while (!done) {
        rte_graph_walk(graph);
    }

Context update when graph walk in action
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The fast-path object for the node is ``struct rte_node``.

It may be possible that in slow-path or after the graph walk-in action,
the user needs to update the context of the node hence access to
``struct rte_node *`` memory.

``rte_graph_foreach_node()``, ``rte_graph_node_get()``,
``rte_graph_node_get_by_name()`` APIs can be used to get the
``struct rte_node*``. ``rte_graph_foreach_node()`` iterator function works on
``struct rte_graph *`` fast-path graph object while others works on graph ID or name.

Get the node statistics using graph cluster
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The user may need to know the aggregate stats of the node across
multiple graph objects. Especially the situation where each graph object bound
to a worker thread.

Introduced a graph cluster object for statistics.
``rte_graph_cluster_stats_create()`` API shall be used for creating a
graph cluster with multiple graph objects and ``rte_graph_cluster_stats_get()``
to get the aggregate node statistics.

An example statistics output from ``rte_graph_cluster_stats_get()``

.. code-block:: diff

    +---------+-----------+-------------+---------------+-----------+---------------+-----------+
    |Node     |calls      |objs         |realloc_count  |objs/call  |objs/sec(10E6) |cycles/call|
    +---------------------+-------------+---------------+-----------+---------------+-----------+
    |node0    |12977424   |3322220544   |5              |256.000    |3047.151872    |20.0000    |
    |node1    |12977653   |3322279168   |0              |256.000    |3047.210496    |17.0000    |
    |node2    |12977696   |3322290176   |0              |256.000    |3047.221504    |17.0000    |
    |node3    |12977734   |3322299904   |0              |256.000    |3047.231232    |17.0000    |
    |node4    |12977784   |3322312704   |1              |256.000    |3047.243776    |17.0000    |
    |node5    |12977825   |3322323200   |0              |256.000    |3047.254528    |17.0000    |
    +---------+-----------+-------------+---------------+-----------+---------------+-----------+

Node writing guidelines
~~~~~~~~~~~~~~~~~~~~~~~

The ``process()`` function of a node is the fast-path function and that needs
to be written carefully to achieve max performance.

Broadly speaking, there are two different types of nodes.

Static nodes
~~~~~~~~~~~~
The first kind of nodes are those that have a fixed ``next_nodes[]`` for the
complete burst (like ethdev_rx, ethdev_tx) and it is simple to write.
``process()`` function can move the obj burst to the next node either using
``rte_node_next_stream_move()`` or using ``rte_node_next_stream_get()`` and
``rte_node_next_stream_put()``.

Intermediate nodes
~~~~~~~~~~~~~~~~~~
The second kind of such node is ``intermediate nodes`` that decide what is the
``next_node[]`` to send to on a per-packet basis. In these nodes,

* Firstly, there has to be the best possible packet processing logic.

* Secondly, each packet needs to be queued to its next node.

This can be done using ``rte_node_enqueue_[x1|x2|x4]()`` APIs if
they are to single next or ``rte_node_enqueue_next()`` that takes array of nexts.

In scenario where multiple intermediate nodes are present but most of the time
each node using the same next node for all its packets, the cost of moving every
pointer from current node's stream to next node's stream could be avoided.
This is called home run and ``rte_node_next_stream_move()`` could be used to
just move stream from the current node to the next node with least number of cycles.
Since this can be avoided only in the case where all the packets are destined
to the same next node, node implementation should be also having worst-case
handling where every packet could be going to different next node.

Example of intermediate node implementation with home run:
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#. Start with speculation that next_node = node->ctx.
   This could be the next_node application used in the previous function call of this node.

#. Get the next_node stream array with required space using
   ``rte_node_next_stream_get(next_node, space)``.

#. while n_left_from > 0 (i.e packets left to be sent) prefetch next pkt_set
   and process current pkt_set to find their next node

#. if all the next nodes of the current pkt_set match speculated next node,
   just count them as successfully speculated(``last_spec``) till now and
   continue the loop without actually moving them to the next node. else if there is
   a mismatch, copy all the pkt_set pointers that were ``last_spec`` and move the
   current pkt_set to their respective next's nodes using ``rte_enqueue_next_x1()``.
   Also, one of the next_node can be updated as speculated next_node if it is more
   probable. Finally, reset ``last_spec`` to zero.

#. if n_left_from != 0 then goto 3) to process remaining packets.

#. if last_spec == nb_objs, All the objects passed were successfully speculated
   to single next node. So, the current stream can be moved to next node using
   ``rte_node_next_stream_move(node, next_node)``.
   This is the ``home run`` where memcpy of buffer pointers to next node is avoided.

#. Update the ``node->ctx`` with more probable next node.

Graph object memory layout
--------------------------
.. _figure_graph_mem_layout:

.. figure:: img/graph_mem_layout.*

   Memory layout

Understanding the memory layout helps to debug the graph library and
improve the performance if needed.

Graph object consists of a header, circular buffer to store the pending
stream when walking over the graph, and variable-length memory to store
the ``rte_node`` objects.

The graph_nodes_mem_create() creates and populate this memory. The functions
such as ``rte_graph_walk()`` and ``rte_node_enqueue_*`` use this memory
to enable fastpath services.

Inbuilt Nodes
-------------

DPDK provides a set of nodes for data processing.
The following diagram depicts inbuilt nodes data flow.

.. _figure_graph_inbuit_node_flow:

.. figure:: img/graph_inbuilt_node_flow.*

   Inbuilt nodes data flow

Following section details the documentation for individual inbuilt node.

ethdev_rx
~~~~~~~~~
This node does ``rte_eth_rx_burst()`` into stream buffer passed to it
(src node stream) and does ``rte_node_next_stream_move()`` only when
there are packets received. Each ``rte_node`` works only on one Rx port and
queue that it gets from node->ctx. For each (port X, rx_queue Y),
a rte_node is cloned from  ethdev_rx_base_node as ``ethdev_rx-X-Y`` in
``rte_node_eth_config()`` along with updating ``node->ctx``.
Each graph needs to be associated  with a unique rte_node for a (port, rx_queue).

ethdev_tx
~~~~~~~~~
This node does ``rte_eth_tx_burst()`` for a burst of objs received by it.
It sends the burst to a fixed Tx Port and Queue information from
node->ctx. For each (port X), this ``rte_node`` is cloned from
ethdev_tx_node_base as "ethdev_tx-X" in ``rte_node_eth_config()``
along with updating node->context.

Since each graph doesn't need more than one Txq, per port, a Txq is assigned
based on graph id to each rte_node instance. Each graph needs to be associated
with a rte_node for each (port).

pkt_drop
~~~~~~~~
This node frees all the objects passed to it considering them as
``rte_mbufs`` that need to be freed.

ip4_lookup
~~~~~~~~~~
This node is an intermediate node that does LPM lookup for the received
ipv4 packets and the result determines each packets next node.

On successful LPM lookup, the result contains the ``next_node`` id and
``next-hop`` id with which the packet needs to be further processed.

On LPM lookup failure, objects are redirected to pkt_drop node.
``rte_node_ip4_route_add()`` is control path API to add ipv4 routes.
To achieve home run, node use ``rte_node_stream_move()`` as mentioned in above
sections.

ip4_rewrite
~~~~~~~~~~~
This node gets packets from ``ip4_lookup`` node with next-hop id for each
packet is embedded in ``node_mbuf_priv1(mbuf)->nh``. This id is used
to determine the L2 header to be written to the packet before sending
the packet out to a particular ethdev_tx node.
``rte_node_ip4_rewrite_add()`` is control path API to add next-hop info.

ip4_reassembly
~~~~~~~~~~~~~~
This node is an intermediate node that reassembles ipv4 fragmented packets,
non-fragmented packets pass through the node un-effected.
The node rewrites its stream and moves it to the next node.
The fragment table and death row table should be setup via the
``rte_node_ip4_reassembly_configure`` API.

ip6_lookup
~~~~~~~~~~
This node is an intermediate node that does LPM lookup for the received
IPv6 packets and the result determines each packets next node.

On successful LPM lookup, the result contains the ``next_node`` ID
and `next-hop`` ID with which the packet needs to be further processed.

On LPM lookup failure, objects are redirected to ``pkt_drop`` node.
``rte_node_ip6_route_add()`` is control path API to add IPv6 routes.
To achieve home run, node use ``rte_node_stream_move()``
as mentioned in above sections.

ip6_rewrite
~~~~~~~~~~~
This node gets packets from ``ip6_lookup`` node with next-hop ID
for each packet is embedded in ``node_mbuf_priv1(mbuf)->nh``.
This ID is used to determine the L2 header to be written to the packet
before sending the packet out to a particular ``ethdev_tx`` node.
``rte_node_ip6_rewrite_add()`` is control path API to add next-hop info.

null
~~~~
This node ignores the set of objects passed to it and reports that all are
processed.

kernel_tx
~~~~~~~~~
This node is an exit node that forwards the packets to kernel.
It will be used to forward any control plane traffic to kernel stack from DPDK.
It uses a raw socket interface to transmit the packets,
it uses the packet's destination IP address in sockaddr_in address structure
and ``sendto`` function to send data on the raw socket.
After sending the burst of packets to kernel,
this node frees up the packet buffers.

kernel_rx
~~~~~~~~~
This node is a source node which receives packets from kernel
and forwards to any of the intermediate nodes.
It uses the raw socket interface to receive packets from kernel.
Uses ``poll`` function to poll on the socket fd
for ``POLLIN`` events to read the packets from raw socket
to stream buffer and does ``rte_node_next_stream_move()``
when there are received packets.

ip4_local
~~~~~~~~~
This node is an intermediate node that does ``packet_type`` lookup for
the received ipv4 packets and the result determines each packets next node.

On successful ``packet_type`` lookup, for any IPv4 protocol the result
contains the ``next_node`` id and ``next-hop`` id with which the packet
needs to be further processed.

On packet_type lookup failure, objects are redirected to ``pkt_drop`` node.
``rte_node_ip4_route_add()`` is control path API to add ipv4 address with 32 bit
depth to receive to packets.
To achieve home run, node use ``rte_node_stream_move()`` as mentioned in above
sections.

udp4_input
~~~~~~~~~~
This node is an intermediate node that does udp destination port lookup for
the received ipv4 packets and the result determines each packets next node.

User registers a new node ``udp4_input`` into graph library during initialization
and attach user specified node as edege to this node using
``rte_node_udp4_usr_node_add()``, and create empty hash table with destination
port and node id as its feilds.

After successful addition of user node as edege, edge id is returned to the user.

User would register ``ip4_lookup`` table with specified ip address and 32 bit as mask
for ip filtration using api ``rte_node_ip4_route_add()``.

After graph is created user would update hash table with custom port with
and previously obtained edge id using API ``rte_node_udp4_dst_port_add()``.

When packet is received lpm look up is performed if ip is matched the packet
is handed over to ip4_local node, then packet is verified for udp proto and
on success packet is enqueued to ``udp4_input`` node.

Hash lookup is performed in ``udp4_input`` node with registered destination port
and destination port in UDP packet , on success packet is handed to ``udp_user_node``.

Feature Arc
-----------
`Feature arc` represents an ordered list of `protocols/features` at a given
networking layer. It is a high level abstraction to connect various `feature`
nodes in `rte_graph` instance and allows seamless packets steering based on the
sequence of enabled features at runtime on each interface.

`Features` (or feature nodes) are nodes which handle partial or complete
protocol processing in a given direction. For instance, `ipv4-rewrite` and
`IPv4 IPsec encryption` are outbound features while `ipv4-lookup` and `IPv4
IPsec decryption` are inbound features.  Further, `ipv4-rewrite` and `IPv4
IPsec encryption` can collectively represent a `feature arc` towards egress
direction with ordering constraints that `IPv4 IPsec encryption` must be
performed before `ipv4-rewrite`.  Similarly, `IPv4 IPsec decryption` and
`ipv4-lookup` can represent a `feature arc` in an ingress direction. Both of
these `feature arc` can co-exist at an IPv4 layer in egress and ingress
direction respectively.

A `feature` can be represented by a single node or collection of multiple nodes
performing feature processing collectively.

.. figure:: img/feature_arc-1.*
   :alt: feature-arc-1
   :width: 350px
   :align: center

   Feature Arc overview

Each `feature arc` is associated with a `Start` node from which all features in
a feature arc are connected.  A `start` node itself is not a `feature` node but
it is where `first enabled feature` is checked in fast path. In above figure,
`Node-A` represents a `start node`.  There may be a `Sink` node as well which
is child node for every feature in an arc.  'Sink` node is responsible of
consuming those packets which are not consumed by intermediate enabled features
between `start` and `sink` node. `Sink` node, if present, is the last enabled
feature in a feature arc. A `feature` node statically connected to `start` node
must also be added via feature arc API, `rte_graph_feature_add()``. Here `Node-B`
acts as a `sink` node which is statically linked to `Node A`. `Feature` nodes
are connected via `rte_graph_feature_add()` which takes care of connecting
all `feature` nodes with each other and start node.

.. code-block:: bash
   :linenos:
   :emphasize-lines: 8
   :caption: Node-B statically linked to Node-A

   static struct rte_node_register node_A_node = {
    .process = node_A_process_func,
            ...
            ...
    .name = "Node-A",
    .next_nodes =
       {
          [0] = "Node-B",
       },
    .nb_edges = 1,
   };

When multiple features are enabled on an interface, it may be required to steer
packets across `features` in a given order. For instance, if `Feature 1` and
`Feature 2` both are enabled on an interface ``X``, it may be required to send
packets to `Feature-1` before `Feature-2`. Such ordering constraints can be
easily expressed with `feature arc`. In this case, `Feature 1` is called as
``First Feature`` and `Feature 2` is called as ``Next Feature`` to `Feature 1`.

.. figure:: img/feature_arc-2.*
   :alt: feature-arc-2
   :width: 600px
   :align: center

   First and Next features and their ordering

In similar manner, even application specific ``custom features`` can be hooked
to standard nodes. It is to be noted that this `custom feature` hooking to
`feature arc` aware node does not require any code changes.

It may be obvious by now that `features` enabled on one interface does not
affect packets on other interfaces. In above example, if no feature is
enabled on an interface ``X``, packets destined to interface ``X`` would be
directly sent to `Node-B` from `Node-A`.

.. figure:: img/feature_arc-3.*
   :alt: feature-arc-3
   :width: 550px
   :align: center

   Feature-2 consumed/non-consumed packet path

When a `Feature-X` node receives packets via feature arc, it may decide whether
to ``consume packet`` or send to `next enabled feature`. A node can consume
packet by freeing it, sending it on wire or enqueuing it to hardware queue.  If a
packet is not consumed by a `Feature-X` node, it may send to `next enabled
feature` on an interface. In above figure, `Feature-2` nodes are represented to
consume packets. Classic example for a node performing consume and non-consume
operation on packets would be IPsec policy node where all packets with
``protect`` actions are consumed while remaining packets with ``bypass``
actions are sent to next enabled feature.

In fast path feature node may require to lookup local data structures for each
interface. For example, retrieving policy database per interface for IPsec
processing.  ``rte_graph_feature_enable`` API allows to set application
specific cookie per feature per interface. `Feature data` object maintains this
cookie in fast path for each interface.

`Feature arc design` allows to enable subsequent features in a control plane
without stopping workers which are accessing feature arc's fast path APIs in
``rte_graph_walk()`` context. However for disabling features require RCU like
scheme for synchronization.

Programming model
~~~~~~~~~~~~~~~~~
Feature Arc Objects
^^^^^^^^^^^^^^^^^^^
Control plane and fast path APIs deals with following objects:

Feature arc
***********
``rte_graph_feature_arc_t`` is a handle to feature arc which is created via
``rte_graph_feature_arc_create()``. It is a `uint64_t` size object which can be
saved in feature node's context. This object can be translated to fast path
feature arc object ``struct rte_graph_feature_arc`` which is an input
argument to all fast path APIs. Control plane APIs majorly takes
`rte_graph_feature_arc_t` object as an input.

Feature List
************
Each feature arc holds two feature lists: `active` and `passive`. While worker
cores uses `active` list, control plane APIs uses `passive` list for
enabling/disabling a feature on any interface with in a arc. After successful
feature enable/disable, ``rte_graph_feature_enable()``/
``rte_graph_feature_disable()`` atomically switches passive list to active list
and vice-versa. Most of the fast path APIs takes active list as an argument
(``rte_graph_feature_rt_list_t``), which feature node can obtain in start of
it's `process_func()` via ``rte_graph_feature_arc_has_any_feature()`` (in `start`
node) or ``rte_graph_feature_arc_has_feature()`` (in next feature nodes).

Each feature list holds RTE_GRAPH_MAX_FEATURES number of features and
associated feature data for every interface index

Feature
********
Feature is a data structure which holds `feature data` object for every
interface.  It is represented via ``rte_graph_feature_t`` which is a `uint8_t`
size object. Fast path internal structure ``struct rte_graph_feature`` can be
obtained from ``rte_graph_feature_t`` via ``rte_graph_feature_get()`` API.

In `start` node `rte_graph_feature_arc_first_feature_get()` can be used to get
first enabled `rte_graph_feature_t` object for an interface. `rte_edge` from
`start` node to first enabled feature is provided by
``rte_graph_feature_arc_feature_set()`` API.

In `feature nodes`, next enabled feature is obtained by providing current feature
as an input to ``rte_graph_feature_arc_next_feature_get()`` API.

Feature data
************
Feature data object is maintained per feature per interface which holds
following information in fast path

- ``rte_edge_t`` to send packet to next enabled feature
- ``Next enabled feature`` on current interface
- ``User_data`` per feature per interface set by application via `rte_graph_feature_enable()`

Enabling Feature Arc processing
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
By default, feature arc processing is disabled in `rte_graph_create()`. To
enable feature arc processing in fast path, `rte_graph_create()` API should be
invoked with `feature_arc_enable` flag set as `true`

.. code-block:: bash
   :linenos:
   :emphasize-lines: 3
   :caption: Enabling feature are processing in rte_graph_create()

    struct rte_graph_param graph_conf;

    graph_conf.feature_arc_enable = true;
    struct rte_graph *graph = rte_graph_create("graph_name", &graph_conf);

Further as an optimization technique, `rte_graph_walk()` would call newly added
``feat_arc_proc()`` node callback function (if non-NULL) instead of
``process``

.. code-block:: bash
   :linenos:
   :emphasize-lines: 3
   :caption: Feature arc specific node callback function

   static struct rte_node_register ip4_rewrite_node = {
        .process = ip4_rewrite_node_process,
        .feat_arc_proc = ip4_rewrite_feature_node_process,
        .name = "ip4_rewrite",
        ...
        ...
   };

If `feat_arc_proc` is not provided in node registration, `process_func` would
be called by `rte_graph_walk()`

Sample Usage
^^^^^^^^^^^^
.. code-block:: bash
   :linenos:
   :caption: Feature arc sample usage

   #define MAX_FEATURES 10
   #define MAX_INDEXES 5

   static uint16_t
   feature2_feature_node_process (struct rte_graph *graph, struct
                                 rte_node *node, void **objs, uint16_t nb_objs)
   {
       /* features may be enabled */
   }
   static uint16_t
   feature2_node_process (struct rte_graph *graph, struct
                                 rte_node *node, void **objs, uint16_t nb_objs)
   {
       /* Feature arc is disabled in rte_graph_create() */
   }

   static uint16_t
   feature2_node_process (struct rte_graph *graph, struct
                                 rte_node *node, void **objs, uint16_t nb_objs)
   {
       /* Feature arc may be enabled or disabled as this process_func() would
        * be called for the case when feature arc is enabled in rte_graph_create()
        * and also the case when it is disabled
        */
   }

   static struct rte_node_register feature2_node = {
        .process = feature2_node_process,
        .feat_arc_proc = feature2_feature_node_process,
        .name = "feature2",
        .init = feature2_init_func,
        ...
        ...
   };

   static struct rte_node_register feature1_node = {
        .process = feature1_node_process,
        .feat_arc_proc = NULL,
        .name = "feature1",
        ...
        ...
   };

   int worker_cb(void *_em)
   {
      rte_graph_feature_arc_t arc;
      uint32_t user_data;

      rte_graph_feature_arc_lookup_by_name("sample_arc", &arc);

      /* From control thread context (like CLII):
       * Enable feature 2 on interface index 4
       */
      if (rte_lcore_id() == rte_get_main_lcore) {
                user_data = 0x1234;
                rte_graph_feature_enable(arc, 4 /* interface index */, "feature2", user_data);
      } else {
                while(1)
                    rte_graph_walk);
      }
   }

   int main(void)
   {
       struct rte_graph_param graph_conf;
       rte_graph_feature_arc_t arc;

       if (rte_graph_feature_arc_create("sample_arc", MAX_FEATURES, MAX_INDEXES, &arc))
           return -1;

       rte_graph_feature_add(arc, "feature1", NULL, NULL);
       rte_graph_feature_add(arc, "feature2", "feature1" /* add feature2 after feature 1*/, NULL);

       /* create graph*/
       ...
       ...
       graph_conf.feature_arc_enable = true;

       struct rte_graph *graph = rte_graph_create("sample_graph", &graph_conf);

       rte_eal_mp_remote_launch(worker_cb, arg, CALL_MAIN);
   }

..  SPDX-License-Identifier: BSD-3-Clause
    Copyright 2017 Mellanox Technologies, Ltd

Generic flow API - examples
===========================

This document demonstrates some concrete examples for programming flow rules
with the ``rte_flow`` APIs.

* Detail of the rte_flow APIs can be found in the following link:
  :doc:`../prog_guide/rte_flow`.

* Details of the TestPMD commands to set the flow rules can be found in the
  following link: :ref:`TestPMD Flow rules <testpmd_rte_flow>`

Simple IPv4 drop
----------------

Description
~~~~~~~~~~~

In this example we will create a simple rule that drops packets whose IPv4
destination equals 192.168.3.2. This code is equivalent to the following
testpmd command (wrapped for clarity)::

  testpmd> flow create 0 ingress pattern eth / vlan /
                    ipv4 dst is 192.168.3.2 / end actions drop / end

Code
~~~~

.. code-block:: c

  /* create the attribute structure */
  struct rte_flow_attr attr = { .ingress = 1 };
  struct rte_flow_item pattern[MAX_PATTERN_IN_FLOW];
  struct rte_flow_action actions[MAX_ACTIONS_IN_FLOW];
  struct rte_flow_item_eth eth;
  struct rte_flow_item_vlan vlan;
  struct rte_flow_item_ipv4 ipv4;
  struct rte_flow *flow;
  struct rte_flow_error error;

  /* setting the eth to pass all packets */
  pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
  pattern[0].spec = &eth;

  /* set the vlan to pass all packets */
  pattern[1] = RTE_FLOW_ITEM_TYPE_VLAN;
  pattern[1].spec = &vlan;

  /* set the dst ipv4 packet to the required value */
  ipv4.hdr.dst_addr = htonl(0xc0a80302);
  pattern[2].type = RTE_FLOW_ITEM_TYPE_IPV4;
  pattern[2].spec = &ipv4;

  /* end the pattern array */
  pattern[3].type = RTE_FLOW_ITEM_TYPE_END;

  /* create the drop action */
  actions[0].type = RTE_FLOW_ACTION_TYPE_DROP;
  actions[1].type = RTE_FLOW_ACTION_TYPE_END;

  /* validate and create the flow rule */
  if (!rte_flow_validate(port_id, &attr, pattern, actions, &error))
      flow = rte_flow_create(port_id, &attr, pattern, actions, &error);

Output
~~~~~~

Terminal 1: running sample app with the flow rule disabled::

  ./filter-program disable
  [waiting for packets]

Terminal 2: running scapy::

  $scapy
  welcome to Scapy
  >> sendp(Ether()/Dot1Q()/IP(src='176.80.50.4', dst='192.168.3.1'), \
           iface='some interface', count=1)
  >> sendp(Ether()/Dot1Q()/IP(src='176.80.50.5', dst='192.168.3.2'), \
           iface='some interface', count=1)

Terminal 1: output log::

  received packet with src ip = 176.80.50.4
  received packet with src ip = 176.80.50.5

Terminal 1: running sample the app flow rule enabled::

  ./filter-program enabled
  [waiting for packets]

Terminal 2: running scapy::

  $scapy
  welcome to Scapy
  >> sendp(Ether()/Dot1Q()/IP(src='176.80.50.4', dst='192.168.3.1'),  \
           iface='some interface', count=1)
  >> sendp(Ether()/Dot1Q()/IP(src='176.80.50.5', dst ='192.168.3.2'), \
           iface='some interface', count=1)

Terminal 1: output log::

  received packet with src ip = 176.80.50.4

Range IPv4 drop
----------------

Description
~~~~~~~~~~~

In this example we will create a simple rule that drops packets whose IPv4
destination is in the range 192.168.3.0 to 192.168.3.255. This is done using
a mask.

This code is equivalent to the following testpmd command (wrapped for
clarity)::

  testpmd> flow create 0 ingress pattern eth / vlan /
                    ipv4 dst spec 192.168.3.0 dst mask 255.255.255.0 /
                    end actions drop / end

Code
~~~~

.. code-block:: c

  struct rte_flow_attr attr = {.ingress = 1};
  struct rte_flow_item pattern[MAX_PATTERN_IN_FLOW];
  struct rte_flow_action actions[MAX_ACTIONS_IN_FLOW];
  struct rte_flow_item_eth eth;
  struct rte_flow_item_vlan vlan;
  struct rte_flow_item_ipv4 ipv4;
  struct rte_flow_item_ipv4 ipv4_mask;
  struct rte_flow *flow;
  struct rte_flow_error error;

  /* setting the eth to pass all packets */
  pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
  pattern[0].spec = &eth;

  /* set the vlan to pass all packets */
  pattern[1] = RTE_FLOW_ITEM_TYPE_VLAN;
  pattern[1].spec = &vlan;

  /* set the dst ipv4 packet to the required value */
  ipv4.hdr.dst_addr = htonl(0xc0a80300);
  ipv4_mask.hdr.dst_addr = htonl(0xffffff00);
  pattern[2].type = RTE_FLOW_ITEM_TYPE_IPV4;
  pattern[2].spec = &ipv4;
  pattern[2].mask = &ipv4_mask;

  /* end the pattern array */
  pattern[3].type = RTE_FLOW_ITEM_TYPE_END;

  /* create the drop action */
  actions[0].type = RTE_FLOW_ACTION_TYPE_DROP;
  actions[1].type = RTE_FLOW_ACTION_TYPE_END;

  /* validate and create the flow rule */
  if (!rte_flow_validate(port_id, &attr, pattern, actions, &error))
      flow = rte_flow_create(port_id, &attr, pattern, actions, &error);

Output
~~~~~~

Terminal 1: running sample app flow rule disabled::

  ./filter-program disable
  [waiting for packets]

Terminal 2: running scapy::

  $scapy
  welcome to Scapy
  >> sendp(Ether()/Dot1Q()/IP(src='176.80.50.4', dst='192.168.3.1'), \
           iface='some interface', count=1)
  >> sendp(Ether()/Dot1Q()/IP(src='176.80.50.5', dst='192.168.3.2'), \
           iface='some interface', count=1)
  >> sendp(Ether()/Dot1Q()/IP(src='176.80.50.6', dst='192.168.5.2'), \
           iface='some interface', count=1)

Terminal 1: output log::

  received packet with src ip = 176.80.50.4
  received packet with src ip = 176.80.50.5
  received packet with src ip = 176.80.50.6

Terminal 1: running sample app flow rule enabled::

  ./filter-program enabled
  [waiting for packets]

Terminal 2: running scapy::

  $scapy
  welcome to Scapy
  >> sendp(Ether()/Dot1Q()/IP(src='176.80.50.4', dst='192.168.3.1'), \
           iface='some interface', count=1)
  >> sendp(Ether()/Dot1Q()/IP(src='176.80.50.5', dst='192.168.3.2'), \
           iface='some interface', count=1)
  >> sendp(Ether()/Dot1Q()/IP(src='176.80.50.6', dst='192.168.5.2'), \
           iface='some interface', count=1)

Terminal 1: output log::

  received packet with src ip = 176.80.50.6

Send vlan to queue
------------------

Description
~~~~~~~~~~~

In this example we will create a rule that routes all vlan id 123 to queue 3.

This code is equivalent to the following testpmd command (wrapped for
clarity)::

  testpmd> flow create 0 ingress pattern eth / vlan vid spec 123 /
                    end actions queue index 3 / end

Code
~~~~

.. code-block:: c

  struct rte_flow_attr attr = { .ingress = 1 };
  struct rte_flow_item pattern[MAX_PATTERN_IN_FLOW];
  struct rte_flow_action actions[MAX_ACTIONS_IN_FLOW];
  struct rte_flow_item_eth eth;
  struct rte_flow_item_vlan vlan;
  struct rte_flow_action_queue queue = { .index = 3 };
  struct rte_flow *flow;
  struct rte_flow_error error;

  /* setting the eth to pass all packets */
  pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
  pattern[0].spec = &eth;

  /* set the vlan to pas all packets */
  vlan.vid = 123;
  pattern[1] = RTE_FLOW_ITEM_TYPE_VLAN;
  pattern[1].spec = &vlan;

  /* end the pattern array */
  pattern[2].type = RTE_FLOW_ITEM_TYPE_END;

  /* create the queue action */
  actions[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
  actions[0].conf = &queue;
  actions[1].type = RTE_FLOW_ACTION_TYPE_END;

  /* validate and create the flow rule */
  if (!rte_flow_validate(port_id, &attr, pattern, actions, &error))
      flow = rte_flow_create(port_id, &attr, pattern, actions, &error);

Output
~~~~~~

Terminal 1: running sample app flow rule disabled::

  ./filter-program disable
  [waiting for packets]

Terminal 2: running scapy::

  $scapy
  welcome to Scapy
  >> sendp(Ether()/Dot1Q(vlan=123)/IP(src='176.80.50.4', dst='192.168.3.1'), \
           iface='some interface', count=1)
  >> sendp(Ether()/Dot1Q(vlan=50)/IP(src='176.80.50.5', dst='192.168.3.2'),  \
           iface='some interface', count=1)
  >> sendp(Ether()/Dot1Q(vlan=123)/IP(src='176.80.50.6', dst='192.168.5.2'), \
           iface='some interface', count=1)

Terminal 1: output log::

  received packet with src ip = 176.80.50.4 sent to queue 2
  received packet with src ip = 176.80.50.5 sent to queue 1
  received packet with src ip = 176.80.50.6 sent to queue 0

Terminal 1: running sample app flow rule enabled::

  ./filter-program enabled
  [waiting for packets]

Terminal 2: running scapy::

  $scapy
  welcome to Scapy
  >> sendp(Ether()/Dot1Q(vlan=123)/IP(src='176.80.50.4', dst='192.168.3.1'), \
           iface='some interface', count=1)
  >> sendp(Ether()/Dot1Q(vlan=50)/IP(src='176.80.50.5', dst='192.168.3.2'),  \
           iface='some interface', count=1)
  >> sendp(Ether()/Dot1Q(vlan=123)/IP(src='176.80.50.6', dst='192.168.5.2'), \
           iface='some interface', count=1)

Terminal 1: output log::

  received packet with src ip = 176.80.50.4 sent to queue 3
  received packet with src ip = 176.80.50.5 sent to queue 1
  received packet with src ip = 176.80.50.6 sent to queue 3

Template API resizable table
----------------------------

Description
~~~~~~~~~~~

A guide to the resizable template table API.

The resizable template table API enables applications to dynamically adjust
capacity of template tables without disrupting the existing flows operation.
The resizable template table API allows applications to optimize the memory
usage and performance of template tables according to the traffic conditions
and requirements.

A typical use case for the resizable template table API

  1. Create a resizable table with the initial capacity.

  2. Change the table flows capacity.

  3. Update flows that were created before the table update.

  4. Complete the table resize procedure.

When application begins to resize the table, it enters the resizable state.
When application finishes resizing the table, it returns to the normal state.
Only a table in the normal state can be resized. After a table is back to
the normal state, application can start a new resize.
Application can add, change or remove flow rules regardless of table state.
Table performance may worsen in the resizable state. Table performance must
recover after the table is back to the normal state.

Table resize procedure must not interfere with flows that existed before
the table size changed.
Flow handles must remain unchanged during table resize.
Application must be able to create new flows and modify or delete existing flows
regardless of the table state.

Application needs to set the `RTE_FLOW_TABLE_SPECIALIZE_RESIZABLE` bit in
the table attributes when creating a template table that can be resized.
The current API cannot make an existing table resizable if it was not created
with the `RTE_FLOW_TABLE_SPECIALIZE_RESIZABLE` bit.
Resizable template table starts in the normal state.

Application can trigger the table to resize by calling
the `rte_flow_template_table_resize()` function. The resize process updates
the PMD table settings and port hardware to fit the new flows capacity.
The resize process must not affect the current flows functionality.
The resize process must not change the current flows handles.
Application can create new flows and modify or delete existing flows
while the table is resizing, but the table performance might be
slower than usual.

Flows that existed before table resize are still functional after table resize.
However, the PMD flow resources that existed before table resize may not be
fully efficient after table resize. In this case, application can combine
the old flow resources from before the resize with the new flow resources
from after the resize.
Application uses the `rte_flow_async_update_resized()` function call to update
flow resources. The flow update process does not interfere with or alter
the existing flow object. It only updates the PMD resources associated with that
flow.
The post-resize flow update process may conflict with application flows
operations, such as creation, removal or update. Therefore, performance-oriented
applications need to choose the best time to call for post-resize flow update.
When application selects flows for the post table resize update, it can iterate
over all existing flows or it can keep track of the flows that need
to be updated.
Flows that were created after the `rte_flow_template_table_resize()`
call finished do not require an update.

To return table to the normal state, use the
`rte_flow_template_table_resize_complete()`. If PMD does not require post-resize
flows update and application does not care about PMD resources optimization,
application can avoid post-resize flows update and move resized table back to
the normal state right after the `rte_flow_template_table_resize()`.
Application can resize the table again when it is in the normal state.

Testpmd commands:(wrapped for clarity)::

  # 1. Create resizable template table for 1 flow.
  testpmd> flow pattern_template 0 create ingress pattern_template_id 3
                template eth / ipv4 / udp src mask 0xffff / end
  testpmd> flow actions_template 0 create ingress actions_template_id 7
                template count  / rss / end
  testpmd> flow template_table 0 create table_id 101 resizable ingress
                group 1 priority 0 rules_number 1
                pattern_template 3 actions_template 7

  # 2. Queue a flow rule.
  testpmd> flow queue 0 create 0 template_table 101
                pattern_template 0 actions_template 0 postpone no
                pattern eth / ipv4 / udp src spec 1 / end actions count / rss / end

  # 3. Resize the template table
  #    The new table capacity is 32 rules
  testpmd> flow template_table 0 resize table_resize_id 101
                table_resize_rules_num 32

  # 4. Queue more flow rules.
  testpmd> flow queue 0 create 0 template_table 101
                pattern_template 0 actions_template 0 postpone no
                pattern eth / ipv4 / udp src spec 2 / end actions count / rss / end
  testpmd> flow queue 0 create 0 template_table 101
                pattern_template 0 actions_template 0 postpone no
                pattern eth / ipv4 / udp src spec 3 / end actions count / rss / end
  testpmd> flow queue 0 create 0 template_table 101
                pattern_template 0 actions_template 0 postpone no
                pattern eth / ipv4 / udp src spec 4 / end actions count / rss / end

  # 5. Queue the initial flow update.
  testpmd> flow queue 0 update_resized 0 rule 0

  # 6. Complete the table resize.
  testpmd> flow template_table 0 resize_complete table 101

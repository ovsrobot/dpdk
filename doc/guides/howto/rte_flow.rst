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

The resizable template table API enables applications to dynamically adjust
capacity of template tables without disrupting the existing flow rules
operation. The resizable template table API allows applications to optimize the
memory usage and performance of template tables according to the traffic
conditions and requirements.

A typical use case for the resizable template table API:

  #. Create a resizable table with the initial capacity.
  #. Change the table flow rules capacity.
  #. Update table flow objects.
  #. Complete the table resize.

A resizable table can be either in normal or resizable state.
When application begins to resize the table, its state is changed to resizable.
The table stays in resizable state until the application finishes resize
procedure.
The application can resize a table in the normal state only.

The application needs to set the ``RTE_FLOW_TABLE_SPECIALIZE_RESIZABLE`` bit in
the table attributes when creating a template table that can be resized,
and the bit cannot be set or cleared later.

The application triggers the table resize by calling
the ``rte_flow_template_table_resize()`` function. The resize process updates
the table configuration to fit the new flow rules capacity.
Table resize does not change existing flow objects configuration.
The application can create new flow rules and modify or delete existing flow
rules while the table is resizing, but the table performance might be
slower than usual.

Flow rules that existed before table resize are fully functional after
table resize. However, the application must update flow objects to match
the new table configuration.
The application calls ``rte_flow_async_update_resized()`` to update flow object
for the new table configuration.
All table flow rules must be updated.

The application calls ``rte_flow_template_table_resize_complete()`` to return a
table to normal state after it completed flow objects update.

Testpmd commands (wrapped for clarity)::

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

  # 5. Queue flow rules updates.
  testpmd> flow queue 0 update_resized 0 rule 0
  testpmd> flow queue 0 update_resized 0 rule 1
  testpmd> flow queue 0 update_resized 0 rule 2
  testpmd> flow queue 0 update_resized 0 rule 3

  # 6. Complete the table resize.
  testpmd> flow template_table 0 resize_complete table 101

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

This example shows how to work with resizable template table.

The code is equivalent to the following testpmd commands:(wrapped for
clarity)::

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

  #6. Complete the table resize.
  flow template_table 0 resize_complete table 101

Code
~~~~

.. code-block:: c

  / * Create resizable table with initial capacity 1. */
  const struct rte_flow_template_table_attr _table_attr_= {
    .nb_flows = 1, /* Initial capacity. */
    .specialize = RTE_FLOW_TABLE_SPECIALIZE_RESIZABLE /* Can resize. */
  };
  struct rte_flow_template_table *_table_;

  _table_ = rte_flow_template_table_create
            (port_id,
            _table_attr_,
            pattern_templates, 1,
            actions_templates, nb_actions_templates, error);

  /* Queue flow rule 0. */
  struct rte_flow *_flow_0_;
  _flow_0_ = rte_flow_async_create
              (port_id, queue_id, op_attr,
              _table_,
              pattern_0, pattern_template_index,
              actions, actions_template_index,
              user_data_0, error);

  /* Resize the table. */
  uint32_t _new_table_capacity_ = 32;
  rte_flow_template_table_resize
              (port_id,
              _table_,
              _new_table_capacity_,
              error);

  /* Create additional flows. */
  struct rte_flow *_flow_1_, *_flow_2_, *_flow_3_;
  _flow_1_ = rte_flow_async_create
              (port_id, queue_id, op_attr,
              _table_,
              pattern_1, pattern_template_index,
              actions, actions_template_index,
              user_data_1, error);
  _flow_2_ = rte_flow_async_create
              (port_id, queue_id, op_attr,
              _table_,
              pattern_2, pattern_template_index,
              actions, actions_template_index,
              user_data_2, error);
  _flow_3_ = rte_flow_async_create
              (port_id, queue_id, op_attr,
              _table_,
              pattern_3, pattern_template_index,
              actions, actions_template_index,
              user_data_3, error);

  /* Queue _flow_0_ update. */
  rte_flow_async_update_resized(port_id, queue, attr,
                                _flow_0_,
                                user_data, error);

  /* Complete table resize. */
  rte_flow_template_table_resize_complete(port_id, _table_, error);

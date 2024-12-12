..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2017 Intel Corporation.

IGB Poll Mode Driver
====================

The IGB PMD (**librte_net_e1000**) provides poll mode driver
support for Intel 1GbE nics.

Supported Chipsets and NICs
---------------------------

- Intel 82576EB 10 Gigabit Ethernet Controller
- Intel 82580EB 10 Gigabit Ethernet Controller
- Intel 82580DB 10 Gigabit Ethernet Controller
- Intel Ethernet Controller I210
- Intel Ethernet Controller I350

Features
--------

Features of the IGB PMD are:

* Multiple queues for TX and RX
* Receiver Side Scaling (RSS)
* MAC/VLAN filtering
* Packet type information
* Double VLAN
* IEEE 1588
* TSO offload
* Checksum offload
* TCP segmentation offload
* Jumbo frames supported

Secondary Process Support
-------------------------

IGB Physical Function Driver
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following ethdev API's are currently not supported for use in secondary processes:

* ``rte_eth_dev_start``
* ``rte_eth_dev_stop``
* ``rte_eth_dev_set_link_up``
* ``rte_eth_dev_set_link_down``
* ``rte_eth_dev_rx_intr_enable``
* ``rte_eth_dev_rx_intr_disable``
* ``rte_eth_link_get``
* ``rte_eth_dev_fw_version_get``
* ``rte_eth_dev_rx_intr_enable``
* ``rte_eth_dev_rx_intr_disable``
* ``rte_eth_dev_led_on``
* ``rte_eth_dev_led_off``
* ``rte_eth_dev_flow_ctrl_set``
* ``rte_eth_dev_default_mac_addr_set``
* ``rte_eth_dev_mac_addr_add``
* ``rte_eth_dev_mac_addr_remove``
* ``rte_eth_dev_set_mc_addr_list``
* ``rte_eth_dev_get_eeprom``
* ``rte_eth_dev_set_eeprom``

IGB Virtual Function Driver
~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following ethdev API's are currently not supported for use in secondary processes:

* ``rte_eth_dev_start``
* ``rte_eth_dev_stop``
* ``rte_eth_promiscuous_enable``
* ``rte_eth_promiscuous_disable``
* ``rte_eth_allmulticast_enable``
* ``rte_eth_allmulticast_disable``
* ``rte_eth_dev_set_link_up``
* ``rte_eth_dev_set_link_down``
* ``rte_eth_link_get``
* ``rte_eth_dev_default_mac_addr_set``
* ``rte_eth_dev_mac_addr_add``
* ``rte_eth_dev_mac_addr_remove``
* ``rte_eth_dev_set_mc_addr_list``

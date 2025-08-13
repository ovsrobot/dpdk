/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 Nebulamatrix Technology Co., Ltd.
 */

#ifndef _NBL_DEF_DEV_H_
#define _NBL_DEF_DEV_H_

#include "nbl_include.h"

#define NBL_DEV_OPS_TBL_TO_OPS(dev_ops_tbl)	((dev_ops_tbl)->ops)
#define NBL_DEV_OPS_TBL_TO_PRIV(dev_ops_tbl)	((dev_ops_tbl)->priv)

struct nbl_dev_ops {
	eth_dev_configure_t        dev_configure; /**< Configure device */
	eth_dev_start_t            dev_start;     /**< Start device */
	eth_dev_stop_t             dev_stop;      /**< Stop device */
	eth_dev_set_link_up_t      dev_set_link_up;   /**< Device link up */
	eth_dev_set_link_down_t    dev_set_link_down; /**< Device link down */
	eth_dev_close_t            dev_close;     /**< Close device */
	eth_dev_reset_t		   dev_reset;	  /**< Reset device */
	eth_link_update_t          link_update;   /**< Get device link state */
	eth_speed_lanes_get_t	   speed_lanes_get;	  /**< Get link speed active lanes */
	eth_speed_lanes_set_t      speed_lanes_set;	  /**< Set link speeds supported lanes */
	/** Get link speed lanes capability */
	eth_speed_lanes_get_capability_t speed_lanes_get_capa;
	/** Check if the device was physically removed */
	eth_is_removed_t           is_removed;

	eth_promiscuous_enable_t   promiscuous_enable; /**< Promiscuous ON */
	eth_promiscuous_disable_t  promiscuous_disable;/**< Promiscuous OFF */
	eth_allmulticast_enable_t  allmulticast_enable;/**< Rx multicast ON */
	eth_allmulticast_disable_t allmulticast_disable;/**< Rx multicast OFF */
	eth_mac_addr_remove_t      mac_addr_remove; /**< Remove MAC address */
	eth_mac_addr_add_t         mac_addr_add;  /**< Add a MAC address */
	eth_mac_addr_set_t         mac_addr_set;  /**< Set a MAC address */
	/** Set list of multicast addresses */
	eth_set_mc_addr_list_t     set_mc_addr_list;
	mtu_set_t                  mtu_set;       /**< Set MTU */

	/** Get generic device statistics */
	eth_stats_get_t            stats_get;
	/** Reset generic device statistics */
	eth_stats_reset_t          stats_reset;
	/** Get extended device statistics */
	eth_xstats_get_t           xstats_get;
	/** Reset extended device statistics */
	eth_xstats_reset_t         xstats_reset;
	/** Get names of extended statistics */
	eth_xstats_get_names_t     xstats_get_names;
	/** Configure per queue stat counter mapping */
	eth_queue_stats_mapping_set_t queue_stats_mapping_set;

	eth_get_module_info_t      get_module_info;
	eth_get_module_eeprom_t    get_module_eeprom;
	reta_update_t              reta_update;   /** Update redirection table. */
	reta_query_t               reta_query;    /** Query redirection table. */
	rss_hash_conf_get_t        rss_hash_conf_get; /** Get current RSS hash configuration. */

	eth_fec_get_capability_t fec_get_capability;
	/**< Get Forward Error Correction(FEC) capability. */
	eth_fec_get_t fec_get;
	/**< Get Forward Error Correction(FEC) mode. */
	eth_fec_set_t fec_set;
	/**< Set Forward Error Correction(FEC) mode. */

	eth_dev_infos_get_t        dev_infos_get; /**< Get device info. */
	eth_rxq_info_get_t         rxq_info_get; /**< retrieve RX queue information. */
	eth_txq_info_get_t         txq_info_get; /**< retrieve TX queue information. */
	eth_burst_mode_get_t       rx_burst_mode_get; /**< Get RX burst mode */
	eth_burst_mode_get_t       tx_burst_mode_get; /**< Get TX burst mode */
	eth_fw_version_get_t       fw_version_get; /**< Get firmware version. */
	eth_dev_supported_ptypes_get_t dev_supported_ptypes_get;
	/**< Get packet types supported and identified by device. */
	eth_dev_ptypes_set_t dev_ptypes_set;
	/**< Inform Ethernet device about reduced range of packet types to handle. */

	vlan_filter_set_t          vlan_filter_set; /**< Filter VLAN Setup. */
	vlan_tpid_set_t            vlan_tpid_set; /**< Outer/Inner VLAN TPID Setup. */
	vlan_strip_queue_set_t     vlan_strip_queue_set; /**< VLAN Stripping on queue. */
	vlan_offload_set_t         vlan_offload_set; /**< Set VLAN Offload. */
	vlan_pvid_set_t            vlan_pvid_set; /**< Set port based TX VLAN insertion. */

	eth_queue_start_t          rx_queue_start;/**< Start RX for a queue. */
	eth_queue_stop_t           rx_queue_stop; /**< Stop RX for a queue. */
	eth_queue_start_t          tx_queue_start;/**< Start TX for a queue. */
	eth_queue_stop_t           tx_queue_stop; /**< Stop TX for a queue. */
	eth_rx_queue_setup_t       rx_queue_setup;/**< Set up device RX queue. */
	eth_queue_release_t        rx_queue_release; /**< Release RX queue. */

	eth_tx_queue_setup_t       tx_queue_setup;/**< Set up device TX queue. */
	eth_queue_release_t        tx_queue_release; /**< Release TX queue. */
	eth_get_eeprom_length_t    get_eeprom_length; /**< Get eeprom length. */
	eth_get_eeprom_t           get_eeprom;        /**< Get eeprom data. */
	eth_set_eeprom_t           set_eeprom;        /**< Set eeprom. */
};

struct nbl_dev_ops_tbl {
	struct nbl_dev_ops *ops;
	void *priv;
};

int nbl_dev_init(void *p, struct rte_eth_dev *eth_dev);
void nbl_dev_remove(void *p);
int nbl_dev_start(void *p);
void nbl_dev_stop(void *p);

#endif

API
===

<!--
  SPDX-License-Identifier: BSD-3-Clause
  Copyright(c) 2013-2017 6WIND S.A.
-->

The public API headers are grouped by topics:

- **device**:
  [bus](@ref rte_bus.h),
  [dev](@ref rte_dev.h),
  [ethdev](@ref rte_ethdev.h),
  [cman](@ref rte_cman.h),
  [ethdev trace fp](@ref rte_ethdev_trace_fp.h),
  [dev info](@ref rte_dev_info.h),
  [ethctrl](@ref rte_eth_ctrl.h),
  [rte_flow](@ref rte_flow.h),
  [rte_tm](@ref rte_tm.h),
  [rte_mtr](@ref rte_mtr.h),
  [bbdev](@ref rte_bbdev.h),
  [bbdev op](@ref rte_bbdev_op.h),
  [bbdev trace fp](@ref rte_bbdev_trace_fp.h),
  [cryptodev](@ref rte_cryptodev.h),
  [crypto](@ref rte_crypto.h),
  [crypto sym](@ref rte_crypto_sym.h),
  [crypto asym](@ref rte_crypto_asym.h),
  [cryptodev trace fp](@ref rte_cryptodev_trace_fp.h),
  [security](@ref rte_security.h),
  [compressdev](@ref rte_compressdev.h),
  [compress](@ref rte_comp.h),
  [regexdev](@ref rte_regexdev.h),
  [mldev](@ref rte_mldev.h),
  [dmadev](@ref rte_dmadev.h),
  [gpudev](@ref rte_gpudev.h),
  [eventdev](@ref rte_eventdev.h),
  [event ring](@ref rte_event_ring.h),
  [eventdev trace fp](@ref rte_eventdev_trace_fp.h),
  [event_eth_rx_adapter](@ref rte_event_eth_rx_adapter.h),
  [event_eth_tx_adapter](@ref rte_event_eth_tx_adapter.h),
  [event_timer_adapter](@ref rte_event_timer_adapter.h),
  [event_crypto_adapter](@ref rte_event_crypto_adapter.h),
  [event_dma_adapter](@ref rte_event_dma_adapter.h),
  [event_vector_adapter](@ref rte_event_vector_adapter.h),
  [rawdev](@ref rte_rawdev.h),
  [metrics](@ref rte_metrics.h),
  [metrics telemetry](@ref rte_metrics_telemetry.h),
  [bitrate](@ref rte_bitrate.h),
  [latency](@ref rte_latencystats.h),
  [devargs](@ref rte_devargs.h),
  [PCI](@ref rte_pci.h),
  [PCI dev feature defs](@ref rte_pci_dev_feature_defs.h),
  [PCI dev features](@ref rte_pci_dev_features.h),
  [bus PCI](@ref rte_bus_pci.h),
  [vdev](@ref rte_bus_vdev.h),
  [vmbus](@ref rte_bus_vmbus.h),
  [vmbus reg](@ref rte_vmbus_reg.h),
  [vfio](@ref rte_vfio.h)

- **device specific**:
  [softnic](@ref rte_eth_softnic.h),
  [bond](@ref rte_eth_bond.h),
  [bond 8023ad](@ref rte_eth_bond_8023ad.h),
  [vhost](@ref rte_vhost.h),
  [vhost async](@ref rte_vhost_async.h),
  [vhost crypto](@ref rte_vhost_crypto.h),
  [eth vhost](@ref rte_eth_vhost.h),
  [vdpa](@ref rte_vdpa.h),
  [ixgbe](@ref rte_pmd_ixgbe.h),
  [i40e](@ref rte_pmd_i40e.h),
  [iavf](@ref rte_pmd_iavf.h),
  [bnxt](@ref rte_pmd_bnxt.h),
  [cnxk](@ref rte_pmd_cnxk.h),
  [cnxk_crypto](@ref rte_pmd_cnxk_crypto.h),
  [cnxk_eventdev](@ref rte_pmd_cnxk_eventdev.h),
  [cnxk_mempool](@ref rte_pmd_cnxk_mempool.h),
  [cnxk gpio](@ref rte_pmd_cnxk_gpio.h),
  [dpaa](@ref rte_pmd_dpaa.h),
  [dpaa2](@ref rte_pmd_dpaa2.h),
  [mlx5](@ref rte_pmd_mlx5.h),
  [dpaa2_mempool](@ref rte_dpaa2_mempool.h),
  [dpaa2_cmdif](@ref rte_pmd_dpaa2_cmdif.h),
  [dpaax_qdma](@ref rte_pmd_dpaax_qdma.h),
  [crypto_scheduler](@ref rte_cryptodev_scheduler.h),
  [crypto scheduler operations](@ref rte_cryptodev_scheduler_operations.h),
  [dlb2](@ref rte_pmd_dlb2.h),
  [ifpga](@ref rte_pmd_ifpga.h),
  [avp common](@ref rte_avp_common.h),
  [avp fifo](@ref rte_avp_fifo.h),
  [ntnic](@ref rte_pmd_ntnic.h),
  [ring](@ref rte_eth_ring.h),
  [txgbe](@ref rte_pmd_txgbe.h),
  [ntb](@ref rte_pmd_ntb.h),
  [acc cfg](@ref rte_acc_cfg.h),
  [acc common cfg](@ref rte_acc_common_cfg.h),
  [fpga 5gnr fec](@ref rte_pmd_fpga_5gnr_fec.h)

- **memory**:
  [per-lcore](@ref rte_per_lcore.h),
  [lcore variables](@ref rte_lcore_var.h),
  [EAL memconfig](@ref rte_eal_memconfig.h),
  [memseg](@ref rte_memory.h),
  [memzone](@ref rte_memzone.h),
  [mempool](@ref rte_mempool.h),
  [mempool trace fp](@ref rte_mempool_trace_fp.h),
  [malloc](@ref rte_malloc.h),
  [memcpy](@ref rte_memcpy.h)

- **timers**:
  [cycles](@ref rte_cycles.h),
  [time](@ref rte_time.h),
  [timer](@ref rte_timer.h),
  [alarm](@ref rte_alarm.h)

- **locks**:
  [atomic](@ref rte_atomic.h),
  [stdatomic](@ref rte_stdatomic.h),
  [lock annotations](@ref rte_lock_annotations.h),
  [mcslock](@ref rte_mcslock.h),
  [pflock](@ref rte_pflock.h),
  [rwlock](@ref rte_rwlock.h),
  [seqcount](@ref rte_seqcount.h),
  [seqlock](@ref rte_seqlock.h),
  [spinlock](@ref rte_spinlock.h),
  [ticketlock](@ref rte_ticketlock.h),
  [RCU](@ref rte_rcu_qsbr.h)

- **CPU arch**:
  [branch prediction](@ref rte_branch_prediction.h),
  [cache prefetch](@ref rte_prefetch.h),
  [SIMD](@ref rte_vect.h),
  [byte order](@ref rte_byteorder.h),
  [CPU flags](@ref rte_cpuflags.h),
  [CPU pause](@ref rte_pause.h),
  [I/O access](@ref rte_io.h),
  [power management](@ref rte_power_intrinsics.h)

- **CPU multicore**:
  [interrupts](@ref rte_interrupts.h),
  [launch](@ref rte_launch.h),
  [lcore](@ref rte_lcore.h),
  [service cores](@ref rte_service.h),
  [service component](@ref rte_service_component.h),
  [keepalive](@ref rte_keepalive.h),
  [power/freq](@ref rte_power_cpufreq.h),
  [power/uncore](@ref rte_power_uncore.h),
  [PMD power](@ref rte_power_pmd_mgmt.h),
  [power guest channel](@ref rte_power_guest_channel.h),
  [power qos](@ref rte_power_qos.h)

- **layers**:
  [ethernet](@ref rte_ether.h),
  [net](@ref rte_net.h),
  [net CRC](@ref rte_net_crc.h),
  [MACsec](@ref rte_macsec.h),
  [ARP](@ref rte_arp.h),
  [HIGIG](@ref rte_higig.h),
  [ICMP](@ref rte_icmp.h),
  [ESP](@ref rte_esp.h),
  [IPsec](@ref rte_ipsec.h),
  [IPsec group](@ref rte_ipsec_group.h),
  [IPsec SA](@ref rte_ipsec_sa.h),
  [IPsec SAD](@ref rte_ipsec_sad.h),
  [IP](@ref rte_ip.h),
  [IPv4](@ref rte_ip4.h),
  [IPv6](@ref rte_ip6.h),
  [frag/reass](@ref rte_ip_frag.h),
  [UDP](@ref rte_udp.h),
  [SCTP](@ref rte_sctp.h),
  [TCP](@ref rte_tcp.h),
  [TLS](@ref rte_tls.h),
  [DTLS](@ref rte_dtls.h),
  [GTP](@ref rte_gtp.h),
  [GRO](@ref rte_gro.h),
  [GSO](@ref rte_gso.h),
  [GRE](@ref rte_gre.h),
  [MPLS](@ref rte_mpls.h),
  [VXLAN](@ref rte_vxlan.h),
  [Geneve](@ref rte_geneve.h),
  [eCPRI](@ref rte_ecpri.h),
  [PDCP hdr](@ref rte_pdcp_hdr.h),
  [PDCP](@ref rte_pdcp.h),
  [L2TPv2](@ref rte_l2tpv2.h),
  [PPP](@ref rte_ppp.h),
  [IB](@ref rte_ib.h),
  [PTP](@ref rte_ptp.h)

- **QoS**:
  [metering](@ref rte_meter.h),
  [scheduler](@ref rte_sched.h),
  [sched common](@ref rte_sched_common.h),
  [RED congestion](@ref rte_red.h),
  [PIE](@ref rte_pie.h)

- **routing**:
  [LPM IPv4 route](@ref rte_lpm.h),
  [LPM IPv6 route](@ref rte_lpm6.h),
  [RIB IPv4](@ref rte_rib.h),
  [RIB IPv6](@ref rte_rib6.h),
  [FIB IPv4](@ref rte_fib.h),
  [FIB IPv6](@ref rte_fib6.h)

- **hashes**:
  [hash](@ref rte_hash.h),
  [jhash](@ref rte_jhash.h),
  [thash](@ref rte_thash.h),
  [thash_gfni](@ref rte_thash_gfni.h),
  [FBK hash](@ref rte_fbk_hash.h),
  [CRC hash](@ref rte_hash_crc.h)

- **classification**
  [reorder](@ref rte_reorder.h),
  [dispatcher](@ref rte_dispatcher.h),
  [distributor](@ref rte_distributor.h),
  [EFD](@ref rte_efd.h),
  [ACL](@ref rte_acl.h),
  [ACL osdep](@ref rte_acl_osdep.h),
  [member](@ref rte_member.h),
  [BPF](@ref rte_bpf.h),
  [BPF def](@ref bpf_def.h),
  [BPF ethdev](@ref rte_bpf_ethdev.h)

- **containers**:
  [mbuf](@ref rte_mbuf.h),
  [mbuf core](@ref rte_mbuf_core.h),
  [mbuf ptype](@ref rte_mbuf_ptype.h),
  [mbuf dyn](@ref rte_mbuf_dyn.h),
  [mbuf history](@ref rte_mbuf_history.h),
  [mbuf pool ops](@ref rte_mbuf_pool_ops.h),
  [ring](@ref rte_ring.h),
  [soring](@ref rte_soring.h),
  [stack](@ref rte_stack.h),
  [tailq](@ref rte_tailq.h),
  [bitset](@ref rte_bitset.h),
  [bitmap](@ref rte_bitmap.h),
  [fbarray](@ref rte_fbarray.h)

- **packet framework**:
  * [port](@ref rte_port.h):
    [ethdev](@ref rte_port_ethdev.h),
    [ring](@ref rte_port_ring.h),
    [frag](@ref rte_port_frag.h),
    [reass](@ref rte_port_ras.h),
    [sched](@ref rte_port_sched.h),
    [src/sink](@ref rte_port_source_sink.h),
    [fd](@ref rte_port_fd.h),
    [sym crypto](@ref rte_port_sym_crypto.h),
    [eventdev](@ref rte_port_eventdev.h)
  * [table](@ref rte_table.h):
    [lpm IPv4](@ref rte_table_lpm.h),
    [lpm IPv6](@ref rte_table_lpm_ipv6.h),
    [ACL](@ref rte_table_acl.h),
    [hash](@ref rte_table_hash.h),
    [array](@ref rte_table_array.h),
    [stub](@ref rte_table_stub.h),
    [LRU](@ref rte_lru.h),
    [hash cuckoo](@ref rte_table_hash_cuckoo.h),
    [hash func](@ref rte_table_hash_func.h)
  * [pipeline](@ref rte_pipeline.h)
    [port_in_action](@ref rte_port_in_action.h)
    [table_action](@ref rte_table_action.h)
  * SWX pipeline:
    [control](@ref rte_swx_ctl.h),
    [extern](@ref rte_swx_extern.h),
    [pipeline](@ref rte_swx_pipeline.h),
    [IPsec](@ref rte_swx_ipsec.h)
  * SWX port:
    [port](@ref rte_swx_port.h),
    [ethdev](@ref rte_swx_port_ethdev.h),
    [fd](@ref rte_swx_port_fd.h),
    [ring](@ref rte_swx_port_ring.h),
    [src/sink](@ref rte_swx_port_source_sink.h)
  * SWX table:
    [table](@ref rte_swx_table.h),
    [table_em](@ref rte_swx_table_em.h),
    [table_wm](@ref rte_swx_table_wm.h),
    [hash func](@ref rte_swx_hash_func.h),
    [table learner](@ref rte_swx_table_learner.h),
    [table selector](@ref rte_swx_table_selector.h)
  * [graph](@ref rte_graph.h):
    [graph_worker](@ref rte_graph_worker.h),
    [graph_feature_arc](@ref rte_graph_feature_arc.h),
    [graph_feature_arc_worker](@ref rte_graph_feature_arc_worker.h)
  * graph_nodes:
    [eth_node](@ref rte_node_eth_api.h),
    [ip4_node](@ref rte_node_ip4_api.h),
    [ip6_node](@ref rte_node_ip6_api.h),
    [udp4_input_node](@ref rte_node_udp4_input_api.h),
    [mbuf_dynfield](@ref rte_node_mbuf_dynfield.h),
    [pkt cls api](@ref rte_node_pkt_cls_api.h)

- **cmdline**:
  [cmdline](@ref cmdline.h),
  [parse](@ref cmdline_parse.h),
  [parse num](@ref cmdline_parse_num.h),
  [parse bool](@ref cmdline_parse_bool.h),
  [parse ipaddr](@ref cmdline_parse_ipaddr.h),
  [parse etheraddr](@ref cmdline_parse_etheraddr.h),
  [parse string](@ref cmdline_parse_string.h),
  [parse portlist](@ref cmdline_parse_portlist.h),
  [rdline](@ref cmdline_rdline.h),
  [vt100](@ref cmdline_vt100.h),
  [socket](@ref cmdline_socket.h),
  [cirbuf](@ref cmdline_cirbuf.h)

- **basic**:
  [bitops](@ref rte_bitops.h),
  [approx fraction](@ref rte_approx.h),
  [random](@ref rte_random.h),
  [checksum](@ref rte_cksum.h),
  [config file](@ref rte_cfgfile.h),
  [key/value args](@ref rte_kvargs.h),
  [argument parsing](@ref rte_argparse.h),
  [ptr_compress](@ref rte_ptr_compress.h),
  [string](@ref rte_string_fns.h),
  [thread](@ref rte_thread.h),
  [reciprocal](@ref rte_reciprocal.h),
  [UUID](@ref rte_uuid.h)

- **debug**:
  [jobstats](@ref rte_jobstats.h),
  [telemetry](@ref rte_telemetry.h),
  [PMU](@ref rte_pmu.h),
  [pcapng](@ref rte_pcapng.h),
  [pdump](@ref rte_pdump.h),
  [hexdump](@ref rte_hexdump.h),
  [debug](@ref rte_debug.h),
  [log](@ref rte_log.h),
  [errno](@ref rte_errno.h),
  [trace](@ref rte_trace.h),
  [EAL trace](@ref rte_eal_trace.h),
  [trace_point](@ref rte_trace_point.h),
  [trace point register](@ref rte_trace_point_register.h)

- **misc**:
  [EAL config](@ref rte_eal.h),
  [class](@ref rte_class.h),
  [common](@ref rte_common.h),
  [epoll](@ref rte_epoll.h),
  [hypervisor](@ref rte_hypervisor.h),
  [OS](@ref rte_os.h),
  [experimental APIs](@ref rte_compat.h),
  [version](@ref rte_version.h)

- **tests**:
  [**DTS**](@dts_api_main_page)

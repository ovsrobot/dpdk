# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2023 University of New Hampshire
# Copyright(c) 2023 PANTHEON.tech s.r.o.
# Copyright(c) 2024 Arm Limited

"""Testpmd interactive shell.

Typical usage example in a TestSuite::

    testpmd_shell = self.sut_node.create_interactive_shell(
            TestPmdShell, privileged=True
        )
    devices = testpmd_shell.get_devices()
    for device in devices:
        print(device)
    testpmd_shell.close()
"""

from dataclasses import dataclass, field
from enum import auto, Enum, Flag, unique
import time
from pathlib import PurePath
from typing import Callable, ClassVar, Literal, NamedTuple
from framework.params import (
    BooleanOption,
    Params,
    bracketed,
    comma_separated,
    Option,
    field_mixins,
    hex_from_flag_value,
    multiple,
    long,
    short,
    str_from_flag_value,
    str_mixins,
)

from framework.exception import InteractiveCommandExecutionError
from framework.params import StrParams
from framework.settings import SETTINGS
from framework.utils import StrEnum

from .interactive_shell import InteractiveShell


@str_mixins(bracketed, comma_separated)
class TestPmdPortNUMAConfig(NamedTuple):
    """DPDK port to NUMA socket association tuple."""

    port: int
    socket: int


@str_mixins(str_from_flag_value)
@unique
class TestPmdFlowDirection(Flag):
    """Flag indicating the direction of the flow.

    A bi-directional flow can be specified with the pipe:

    >>> TestPmdFlowDirection.RX | TestPmdFlowDirection.TX
    <TestPmdFlowDirection.TX|RX: 3>
    """

    #:
    RX = 1 << 0
    #:
    TX = 1 << 1


@str_mixins(bracketed, comma_separated)
class TestPmdRingNUMAConfig(NamedTuple):
    """Tuple associating DPDK port, direction of the flow and NUMA socket."""

    port: int
    direction: TestPmdFlowDirection
    socket: int


@str_mixins(comma_separated)
class TestPmdEthPeer(NamedTuple):
    """Tuple associating a MAC address to the specified DPDK port."""

    port_no: int
    mac_address: str


@str_mixins(comma_separated)
class TestPmdTxIPAddrPair(NamedTuple):
    """Tuple specifying the source and destination IPs for the packets."""

    source_ip: str
    dest_ip: str


@str_mixins(comma_separated)
class TestPmdTxUDPPortPair(NamedTuple):
    """Tuple specifying the UDP source and destination ports for the packets.

    If leaving ``dest_port`` unspecified, ``source_port`` will be used for the destination port as well.
    """

    source_port: int
    dest_port: int | None = None


class TestPmdPortTopology(StrEnum):
    paired = auto()
    """In paired mode, the forwarding is between pairs of ports,
    for example: (0,1), (2,3), (4,5)."""
    chained = auto()
    """In chained mode, the forwarding is to the next available port in the port mask,
    for example: (0,1), (1,2), (2,0).

    The ordering of the ports can be changed using the portlist testpmd runtime function.
    """
    loop = auto()
    """In loop mode, ingress traffic is simply transmitted back on the same interface."""


class TestPmdForwardingModes(StrEnum):
    r"""The supported packet forwarding modes for :class:`~TestPmdShell`\s."""

    #:
    io = auto()
    #:
    mac = auto()
    #:
    macswap = auto()
    #:
    flowgen = auto()
    #:
    rxonly = auto()
    #:
    txonly = auto()
    #:
    csum = auto()
    #:
    icmpecho = auto()
    #:
    ieee1588 = auto()
    #:
    noisy = auto()
    #:
    fivetswap = "5tswap"
    #:
    shared_rxq = "shared-rxq"
    #:
    recycle_mbufs = auto()


@str_mixins(comma_separated)
class XYPair(NamedTuple):
    #:
    X: int
    #:
    Y: int | None = None


@str_mixins(hex_from_flag_value)
@unique
class TestPmdRXMultiQueueMode(Flag):
    #:
    RSS = 1 << 0
    #:
    DCB = 1 << 1
    #:
    VMDQ = 1 << 2


@str_mixins(hex_from_flag_value)
@unique
class TestPmdHairpinMode(Flag):
    TWO_PORTS_LOOP = 1 << 0
    """Two hairpin ports loop."""
    TWO_PORTS_PAIRED = 1 << 1
    """Two hairpin ports paired."""
    EXPLICIT_TX_FLOW = 1 << 4
    """Explicit Tx flow rule."""
    FORCE_RX_QUEUE_MEM_SETTINGS = 1 << 8
    """Force memory settings of hairpin RX queue."""
    FORCE_TX_QUEUE_MEM_SETTINGS = 1 << 9
    """Force memory settings of hairpin TX queue."""
    RX_QUEUE_USE_LOCKED_DEVICE_MEMORY = 1 << 12
    """Hairpin RX queues will use locked device memory."""
    RX_QUEUE_USE_RTE_MEMORY = 1 << 13
    """Hairpin RX queues will use RTE memory."""
    TX_QUEUE_USE_LOCKED_DEVICE_MEMORY = 1 << 16
    """Hairpin TX queues will use locked device memory."""
    TX_QUEUE_USE_RTE_MEMORY = 1 << 18
    """Hairpin TX queues will use RTE memory."""


class TestPmdEvent(StrEnum):
    #:
    unknown = auto()
    #:
    queue_state = auto()
    #:
    vf_mbox = auto()
    #:
    macsec = auto()
    #:
    intr_lsc = auto()
    #:
    intr_rmv = auto()
    #:
    intr_reset = auto()
    #:
    dev_probed = auto()
    #:
    dev_released = auto()
    #:
    flow_aged = auto()
    #:
    err_recovering = auto()
    #:
    recovery_success = auto()
    #:
    recovery_failed = auto()
    #:
    all = auto()


class TestPmdMempoolAllocationMode(StrEnum):
    native = auto()
    """Create and populate mempool using native DPDK memory."""
    anon = auto()
    """Create mempool using native DPDK memory, but populate using anonymous memory."""
    xmem = auto()
    """Create and populate mempool using externally and anonymously allocated area."""
    xmemhuge = auto()
    """Create and populate mempool using externally and anonymously allocated hugepage area."""


@dataclass(kw_only=True)
class TestPmdTXOnlyForwardingMode(Params):
    __forward_mode: Literal[TestPmdForwardingModes.txonly] = field(
        default=TestPmdForwardingModes.txonly, init=False, metadata=long("forward-mode")
    )
    multi_flow: Option = field(default=None, metadata=long("txonly-multi-flow"))
    """Generate multiple flows."""
    segments_length: XYPair | None = field(default=None, metadata=long("txpkts"))
    """Set TX segment sizes or total packet length."""


@dataclass(kw_only=True)
class TestPmdFlowGenForwardingMode(Params):
    __forward_mode: Literal[TestPmdForwardingModes.flowgen] = field(
        default=TestPmdForwardingModes.flowgen, init=False, metadata=long("forward-mode")
    )
    clones: int | None = field(default=None, metadata=long("flowgen-clones"))
    """Set the number of each packet clones to be sent. Sending clones reduces host CPU load on
    creating packets and may help in testing extreme speeds or maxing out Tx packet performance.
    N should be not zero, but less than ‘burst’ parameter.
    """
    flows: int | None = field(default=None, metadata=long("flowgen-flows"))
    """Set the number of flows to be generated, where 1 <= N <= INT32_MAX."""
    segments_length: XYPair | None = field(default=None, metadata=long("txpkts"))
    """Set TX segment sizes or total packet length."""


@dataclass(kw_only=True)
class TestPmdNoisyForwardingMode(Params):
    __forward_mode: Literal[TestPmdForwardingModes.noisy] = field(
        default=TestPmdForwardingModes.noisy, init=False, metadata=long("forward-mode")
    )
    forward_mode: (
        Literal[
            TestPmdForwardingModes.io,
            TestPmdForwardingModes.mac,
            TestPmdForwardingModes.macswap,
            TestPmdForwardingModes.fivetswap,
        ]
        | None
    ) = field(default=TestPmdForwardingModes.io, metadata=long("noisy-forward-mode"))
    """Set the noisy vnf forwarding mode."""
    tx_sw_buffer_size: int | None = field(default=None, metadata=long("noisy-tx-sw-buffer-size"))
    """Set the maximum number of elements of the FIFO queue to be created for buffering packets.
    The default value is 0.
    """
    tx_sw_buffer_flushtime: int | None = field(
        default=None, metadata=long("noisy-tx-sw-buffer-flushtime")
    )
    """Set the time before packets in the FIFO queue are flushed. The default value is 0."""
    lkup_memory: int | None = field(default=None, metadata=long("noisy-lkup-memory"))
    """Set the size of the noisy neighbor simulation memory buffer in MB to N. The default value is 0."""
    lkup_num_reads: int | None = field(default=None, metadata=long("noisy-lkup-num-reads"))
    """Set the number of reads to be done in noisy neighbor simulation memory buffer to N.
    The default value is 0.
    """
    lkup_num_writes: int | None = field(default=None, metadata=long("noisy-lkup-num-writes"))
    """Set the number of writes to be done in noisy neighbor simulation memory buffer to N.
    The default value is 0.
    """
    lkup_num_reads_writes: int | None = field(
        default=None, metadata=long("noisy-lkup-num-reads-writes")
    )
    """Set the number of r/w accesses to be done in noisy neighbor simulation memory buffer to N.
    The default value is 0.
    """


@dataclass(kw_only=True)
class TestPmdAnonMempoolAllocationMode(Params):
    __mp_alloc: Literal[TestPmdMempoolAllocationMode.anon] = field(
        default=TestPmdMempoolAllocationMode.anon, init=False, metadata=long("mp-alloc")
    )
    no_iova_contig: Option = None
    """Enable to create mempool which is not IOVA contiguous."""


@dataclass(kw_only=True)
class TestPmdRXRingParams(Params):
    descriptors: int | None = field(default=None, metadata=long("rxd"))
    """Set the number of descriptors in the RX rings to N, where N > 0. The default value is 128."""
    prefetch_threshold: int | None = field(default=None, metadata=long("rxpt"))
    """Set the prefetch threshold register of RX rings to N, where N >= 0. The default value is 8."""
    host_threshold: int | None = field(default=None, metadata=long("rxht"))
    """Set the host threshold register of RX rings to N, where N >= 0. The default value is 8."""
    write_back_threshold: int | None = field(default=None, metadata=long("rxwt"))
    """Set the write-back threshold register of RX rings to N, where N >= 0. The default value is 4."""
    free_threshold: int | None = field(default=None, metadata=long("rxfreet"))
    """Set the free threshold of RX descriptors to N, where 0 <= N < value of ``-–rxd``.
    The default value is 0.
    """


@dataclass
class TestPmdDisableRSS(Params):
    """Disable RSS (Receive Side Scaling)."""

    __disable_rss: Literal[True] = field(default=True, init=False, metadata=long("disable-rss"))


@dataclass
class TestPmdSetRSSIPOnly(Params):
    """Set RSS functions for IPv4/IPv6 only."""

    __rss_ip: Literal[True] = field(default=True, init=False, metadata=long("rss-ip"))


@dataclass
class TestPmdSetRSSUDP(Params):
    """Set RSS functions for IPv4/IPv6 and UDP."""

    __rss_udp: Literal[True] = field(default=True, init=False, metadata=long("rss-udp"))


@dataclass(kw_only=True)
class TestPmdTXRingParams(Params):
    descriptors: int | None = field(default=None, metadata=long("txd"))
    """Set the number of descriptors in the TX rings to N, where N > 0. The default value is 512."""
    rs_bit_threshold: int | None = field(default=None, metadata=long("txrst"))
    """Set the transmit RS bit threshold of TX rings to N, where 0 <= N <= value of ``--txd``.
    The default value is 0.
    """
    prefetch_threshold: int | None = field(default=None, metadata=long("txpt"))
    """Set the prefetch threshold register of TX rings to N, where N >= 0. The default value is 36."""
    host_threshold: int | None = field(default=None, metadata=long("txht"))
    """Set the host threshold register of TX rings to N, where N >= 0. The default value is 0."""
    write_back_threshold: int | None = field(default=None, metadata=long("txwt"))
    """Set the write-back threshold register of TX rings to N, where N >= 0. The default value is 0."""
    free_threshold: int | None = field(default=None, metadata=long("txfreet"))
    """Set the transmit free threshold of TX rings to N, where 0 <= N <= value of ``--txd``.
    The default value is 0.
    """


@dataclass(slots=True, kw_only=True)
class TestPmdParameters(Params):
    """The testpmd shell parameters.

    The string representation can be created by converting the instance to a string.
    """

    interactive_mode: Option = field(default=True, metadata=short("i"))
    """Runs testpmd in interactive mode."""
    auto_start: Option = field(default=None, metadata=short("a"))
    """Start forwarding on initialization."""
    tx_first: Option = None
    """Start forwarding, after sending a burst of packets first."""

    stats_period: int | None = None
    """Display statistics every ``PERIOD`` seconds, if interactive mode is disabled.
    The default value is 0, which means that the statistics will not be displayed.

    .. note:: This flag should be used only in non-interactive mode.
    """

    display_xstats: list[str] | None = field(default=None, metadata=field_mixins(comma_separated))
    """Display comma-separated list of extended statistics every ``PERIOD`` seconds as specified in
    ``--stats-period`` or when used with interactive commands that show Rx/Tx statistics
    (i.e. ‘show port stats’).
    """

    nb_cores: int | None = 1
    """Set the number of forwarding cores, where 1 <= N <= “number of cores” or ``RTE_MAX_LCORE``
    from the configuration file. The default value is 1.
    """
    coremask: int | None = field(default=None, metadata=field_mixins(hex))
    """Set the hexadecimal bitmask of the cores running the packet forwarding test. The main lcore
    is reserved for command line parsing only and cannot be masked on for packet forwarding.
    """

    nb_ports: int | None = None
    """Set the number of forwarding ports, where 1 <= N <= “number of ports” on the board or
    ``RTE_MAX_ETHPORTS`` from the configuration file. The default value is the number of ports
    on the board.
    """
    port_topology: TestPmdPortTopology | None = TestPmdPortTopology.paired
    """Set port topology, where mode is paired (the default), chained or loop."""
    portmask: int | None = field(default=None, metadata=field_mixins(hex))
    """Set the hexadecimal bitmask of the ports used by the packet forwarding test."""
    portlist: str | None = None  # TODO: can be ranges 0,1-3
    """Set the forwarding ports based on the user input used by the packet forwarding test.
    ‘-‘ denotes a range of ports to set including the two specified port IDs ‘,’ separates
    multiple port values. Possible examples like –portlist=0,1 or –portlist=0-2 or –portlist=0,1-2 etc
    """

    numa: BooleanOption = True
    """Enable/disable NUMA-aware allocation of RX/TX rings and of RX memory buffers (mbufs). Enabled by default."""
    socket_num: int | None = None
    """Set the socket from which all memory is allocated in NUMA mode, where 0 <= N < number of sockets on the board."""
    port_numa_config: list[TestPmdPortNUMAConfig] | None = field(
        default=None, metadata=field_mixins(comma_separated)
    )
    """Specify the socket on which the memory pool to be used by the port will be allocated."""
    ring_numa_config: list[TestPmdRingNUMAConfig] | None = field(
        default=None, metadata=field_mixins(comma_separated)
    )
    """Specify the socket on which the TX/RX rings for the port will be allocated.
    Where flag is 1 for RX, 2 for TX, and 3 for RX and TX.
    """

    # Mbufs
    total_num_mbufs: int | None = None
    """Set the number of mbufs to be allocated in the mbuf pools, where N > 1024."""
    mbuf_size: list[int] | None = field(default=None, metadata=field_mixins(comma_separated))
    """Set the data size of the mbufs used to N bytes, where N < 65536. The default value is 2048.
    If multiple mbuf-size values are specified the extra memory pools will be created for
    allocating mbufs to receive packets with buffer splitting features.
    """
    mbcache: int | None = None
    """Set the cache of mbuf memory pools to N, where 0 <= N <= 512. The default value is 16."""

    max_pkt_len: int | None = None
    """Set the maximum packet size to N bytes, where N >= 64. The default value is 1518."""

    eth_peers_configfile: PurePath | None = None
    """Use a configuration file containing the Ethernet addresses of the peer ports."""
    eth_peer: list[TestPmdEthPeer] | None = field(default=None, metadata=multiple())
    """Set the MAC address XX:XX:XX:XX:XX:XX of the peer port N, where 0 <= N < RTE_MAX_ETHPORTS."""

    tx_ip: TestPmdTxIPAddrPair | None = TestPmdTxIPAddrPair(
        source_ip="198.18.0.1", dest_ip="198.18.0.2"
    )
    """Set the source and destination IP address used when doing transmit only test.
    The defaults address values are source 198.18.0.1 and destination 198.18.0.2.
    These are special purpose addresses reserved for benchmarking (RFC 5735).
    """
    tx_udp: TestPmdTxUDPPortPair | None = TestPmdTxUDPPortPair(9)
    """Set the source and destination UDP port number for transmit test only test.
    The default port is the port 9 which is defined for the discard protocol (RFC 863)."""

    enable_lro: Option = None
    """Enable large receive offload."""
    max_lro_pkt_size: int | None = None
    """Set the maximum LRO aggregated packet size to N bytes, where N >= 64."""

    disable_crc_strip: Option = None
    """Disable hardware CRC stripping."""
    enable_scatter: Option = None
    """Enable scatter (multi-segment) RX."""
    enable_hw_vlan: Option = None
    """Enable hardware VLAN."""
    enable_hw_vlan_filter: Option = None
    """Enable hardware VLAN filter."""
    enable_hw_vlan_strip: Option = None
    """Enable hardware VLAN strip."""
    enable_hw_vlan_extend: Option = None
    """Enable hardware VLAN extend."""
    enable_hw_qinq_strip: Option = None
    """Enable hardware QINQ strip."""
    pkt_drop_enabled: Option = field(default=None, metadata=long("enable-drop-en"))
    """Enable per-queue packet drop for packets with no descriptors."""

    rss: TestPmdDisableRSS | TestPmdSetRSSIPOnly | TestPmdSetRSSUDP | None = None
    """RSS option setting.

    The value can be one of:
    * :class:`TestPmdDisableRSS`, to disable RSS
    * :class:`TestPmdSetRSSIPOnly`, to set RSS for IPv4/IPv6 only
    * :class:`TestPmdSetRSSUDP`, to set RSS for IPv4/IPv6 and UDP
    """

    forward_mode: (
        Literal[
            TestPmdForwardingModes.io,
            TestPmdForwardingModes.mac,
            TestPmdForwardingModes.macswap,
            TestPmdForwardingModes.rxonly,
            TestPmdForwardingModes.csum,
            TestPmdForwardingModes.icmpecho,
            TestPmdForwardingModes.ieee1588,
            TestPmdForwardingModes.fivetswap,
            TestPmdForwardingModes.shared_rxq,
            TestPmdForwardingModes.recycle_mbufs,
        ]
        | TestPmdFlowGenForwardingMode
        | TestPmdTXOnlyForwardingMode
        | TestPmdNoisyForwardingMode
        | None
    ) = TestPmdForwardingModes.io
    """Set the forwarding mode.

    The value can be one of:
    * :attr:`TestPmdForwardingModes.io` (default)
    * :attr:`TestPmdForwardingModes.mac`
    * :attr:`TestPmdForwardingModes.rxonly`
    * :attr:`TestPmdForwardingModes.csum`
    * :attr:`TestPmdForwardingModes.icmpecho`
    * :attr:`TestPmdForwardingModes.ieee1588`
    * :attr:`TestPmdForwardingModes.fivetswap`
    * :attr:`TestPmdForwardingModes.shared_rxq`
    * :attr:`TestPmdForwardingModes.recycle_mbufs`
    * :class:`FlowGenForwardingMode`
    * :class:`TXOnlyForwardingMode`
    * :class:`NoisyForwardingMode`
    """

    hairpin_mode: TestPmdHairpinMode | None = TestPmdHairpinMode(0)
    """Set the hairpin port configuration."""
    hairpin_queues: int | None = field(default=None, metadata=long("hairpinq"))
    """Set the number of hairpin queues per port to N, where 1 <= N <= 65535. The default value is 0."""

    burst: int | None = None
    """Set the number of packets per burst to N, where 1 <= N <= 512. The default value is 32.
    If set to 0, driver default is used if defined.
    Else, if driver default is not defined, default of 32 is used.
    """

    # RX data parameters
    enable_rx_cksum: Option = None
    """Enable hardware RX checksum offload."""
    rx_queues: int | None = field(default=None, metadata=long("rxq"))
    """Set the number of RX queues per port to N, where 1 <= N <= 65535. The default value is 1."""
    rx_ring: TestPmdRXRingParams | None = None
    """Set the RX rings parameters."""
    no_flush_rx: Option = None
    """Don’t flush the RX streams before starting forwarding. Used mainly with the PCAP PMD."""
    rx_segments_offsets: XYPair | None = field(default=None, metadata=long("rxoffs"))
    """Set the offsets of packet segments on receiving if split feature is engaged.
    Affects only the queues configured with split offloads (currently BUFFER_SPLIT is supported only).
    """
    rx_segments_length: XYPair | None = field(default=None, metadata=long("rxpkts"))
    """Set the length of segments to scatter packets on receiving if split feature is engaged.
    Affects only the queues configured with split offloads (currently BUFFER_SPLIT is supported only).
    Optionally the multiple memory pools can be specified with –mbuf-size command line parameter and
    the mbufs to receive will be allocated sequentially from these extra memory pools.
    """
    multi_rx_mempool: Option = None
    """Enable multiple mbuf pools per Rx queue."""
    rx_shared_queue: Option | int = field(default=None, metadata=long("rxq-share"))
    """Create queues in shared Rx queue mode if device supports. Shared Rx queues are grouped per X ports.
    X defaults to UINT32_MAX, implies all ports join share group 1.
    Forwarding engine “shared-rxq” should be used for shared Rx queues.
    This engine does Rx only and update stream statistics accordingly.
    """
    rx_offloads: int | None = field(default=0, metadata=field_mixins(hex))
    """Set the hexadecimal bitmask of RX queue offloads. The default value is 0."""
    rx_mq_mode: TestPmdRXMultiQueueMode | None = (
        TestPmdRXMultiQueueMode.DCB | TestPmdRXMultiQueueMode.RSS | TestPmdRXMultiQueueMode.VMDQ
    )
    """Set the hexadecimal bitmask of RX multi queue mode which can be enabled."""

    # TX data parameters
    tx_queues: int | None = field(default=None, metadata=long("txq"))
    """Set the number of TX queues per port to N, where 1 <= N <= 65535. The default value is 1."""
    tx_ring: TestPmdTXRingParams | None = None
    """Set the TX rings params."""
    tx_offloads: int | None = field(default=0, metadata=field_mixins(hex))
    """Set the hexadecimal bitmask of TX queue offloads. The default value is 0."""

    eth_link_speed: int | None = None
    """Set a forced link speed to the ethernet port. E.g. 1000 for 1Gbps."""
    disable_link_check: Option = None
    """Disable check on link status when starting/stopping ports."""
    disable_device_start: Option = None
    """Do not automatically start all ports.
    This allows testing configuration of rx and tx queues before device is started for the first time.
    """
    no_lsc_interrupt: Option = None
    """Disable LSC interrupts for all ports, even those supporting it."""
    no_rmv_interrupt: Option = None
    """Disable RMV interrupts for all ports, even those supporting it."""
    bitrate_stats: int | None = None
    """Set the logical core N to perform bitrate calculation."""
    latencystats: int | None = None
    """Set the logical core N to perform latency and jitter calculations."""
    print_events: list[TestPmdEvent] | None = field(
        default=None, metadata=multiple(long("print-event"))
    )
    """Enable printing the occurrence of the designated events.
    Using :attr:`TestPmdEvent.ALL` will enable all of them.
    """
    mask_events: list[TestPmdEvent] | None = field(
        default_factory=lambda: [TestPmdEvent.intr_lsc], metadata=multiple(long("mask-event"))
    )
    """Disable printing the occurrence of the designated events.
    Using :attr:`TestPmdEvent.ALL` will disable all of them.
    """

    flow_isolate_all: Option = None
    """Providing this parameter requests flow API isolated mode on all ports at initialization time.
    It ensures all traffic is received through the configured flow rules only (see flow command).

    Ports that do not support this mode are automatically discarded.
    """
    disable_flow_flush: Option = None
    """Disable port flow flush when stopping port.
    This allows testing keep flow rules or shared flow objects across restart.
    """

    hot_plug: Option = None
    """Enable device event monitor mechanism for hotplug."""
    vxlan_gpe_port: int | None = None
    """Set the UDP port number of tunnel VXLAN-GPE to N. The default value is 4790."""
    geneve_parsed_port: int | None = None
    """Set the UDP port number that is used for parsing the GENEVE protocol to N.
    HW may be configured with another tunnel Geneve port. The default value is 6081.
    """
    lock_all_memory: BooleanOption = field(default=False, metadata=long("mlockall"))
    """Enable/disable locking all memory. Disabled by default."""
    mempool_allocation_mode: (
        Literal[
            TestPmdMempoolAllocationMode.native,
            TestPmdMempoolAllocationMode.xmem,
            TestPmdMempoolAllocationMode.xmemhuge,
        ]
        | TestPmdAnonMempoolAllocationMode
        | None
    ) = field(default=None, metadata=long("mp-alloc"))
    """Select mempool allocation mode.

    The value can be one of:
    * :attr:`TestPmdMempoolAllocationMode.native`
    * :class:`TestPmdAnonMempoolAllocationMode`
    * :attr:`TestPmdMempoolAllocationMode.xmem`
    * :attr:`TestPmdMempoolAllocationMode.xmemhuge`
    """
    record_core_cycles: Option = None
    """Enable measurement of CPU cycles per packet."""
    record_burst_status: Option = None
    """Enable display of RX and TX burst stats."""


class TestPmdDevice(object):
    """The data of a device that testpmd can recognize.

    Attributes:
        pci_address: The PCI address of the device.
    """

    pci_address: str

    def __init__(self, pci_address_line: str):
        """Initialize the device from the testpmd output line string.

        Args:
            pci_address_line: A line of testpmd output that contains a device.
        """
        self.pci_address = pci_address_line.strip().split(": ")[1].strip()

    def __str__(self) -> str:
        """The PCI address captures what the device is."""
        return self.pci_address


@dataclass(slots=True)
class TestPmdState:
    """Session state container."""

    #:
    packet_forwarding_started: bool = False

    #: The number of ports which were allowed on the command-line when testpmd was started.
    number_of_ports: int = 0


class TestPmdShell(InteractiveShell):
    """Testpmd interactive shell.

    The testpmd shell users should never use
    the :meth:`~.interactive_shell.InteractiveShell.send_command` method directly, but rather
    call specialized methods. If there isn't one that satisfies a need, it should be added.
    """

    #: Current state
    state: TestPmdState = TestPmdState()

    #: The path to the testpmd executable.
    path: ClassVar[PurePath] = PurePath("app", "dpdk-testpmd")

    #: Flag this as a DPDK app so that it's clear this is not a system app and
    #: needs to be looked in a specific path.
    dpdk_app: ClassVar[bool] = True

    #: The testpmd's prompt.
    _default_prompt: ClassVar[str] = "testpmd>"

    #: This forces the prompt to appear after sending a command.
    _command_extra_chars: ClassVar[str] = "\n"

    def _start_application(self, get_privileged_command: Callable[[str], str] | None) -> None:
        """Overrides :meth:`~.interactive_shell._start_application`.

        Add flags for starting testpmd in interactive mode and disabling messages for link state
        change events before starting the application. Link state is verified before starting
        packet forwarding and the messages create unexpected newlines in the terminal which
        complicates output collection.

        Also find the number of pci addresses which were allowed on the command line when the app
        was started.
        """
        from framework.testbed_model.sut_node import EalParameters

        assert isinstance(self._app_args, EalParameters)

        if self._app_args.app_params is None:
            self._app_args.app_params = TestPmdParameters()

        assert isinstance(self._app_args.app_params, TestPmdParameters)

        if self._app_args.app_params.auto_start:
            self.state.packet_forwarding_started = True

        if self._app_args.ports is not None:
            self.state.number_of_ports = len(self._app_args.ports)

        super()._start_application(get_privileged_command)

    def start(self, verify: bool = True) -> None:
        """Start packet forwarding with the current configuration.

        Args:
            verify: If :data:`True` , a second start command will be sent in an attempt to verify
                packet forwarding started as expected.

        Raises:
            InteractiveCommandExecutionError: If `verify` is :data:`True` and forwarding fails to
                start or ports fail to come up.
        """
        self.send_command("start")
        if verify:
            # If forwarding was already started, sending "start" again should tell us
            start_cmd_output = self.send_command("start")
            if "Packet forwarding already started" not in start_cmd_output:
                self._logger.debug(f"Failed to start packet forwarding: \n{start_cmd_output}")
                raise InteractiveCommandExecutionError("Testpmd failed to start packet forwarding.")

            for port_id in range(self.state.number_of_ports):
                if not self.wait_link_status_up(port_id):
                    raise InteractiveCommandExecutionError(
                        "Not all ports came up after starting packet forwarding in testpmd."
                    )

        self.state.packet_forwarding_started = True

    def stop(self, verify: bool = True) -> None:
        """Stop packet forwarding.

        Args:
            verify: If :data:`True` , the output of the stop command is scanned to verify that
                forwarding was stopped successfully or not started. If neither is found, it is
                considered an error.

        Raises:
            InteractiveCommandExecutionError: If `verify` is :data:`True` and the command to stop
                forwarding results in an error.
        """
        stop_cmd_output = self.send_command("stop")
        if verify:
            if (
                "Done." not in stop_cmd_output
                and "Packet forwarding not started" not in stop_cmd_output
            ):
                self._logger.debug(f"Failed to stop packet forwarding: \n{stop_cmd_output}")
                raise InteractiveCommandExecutionError("Testpmd failed to stop packet forwarding.")

        self.state.packet_forwarding_started = False

    def get_devices(self) -> list[TestPmdDevice]:
        """Get a list of device names that are known to testpmd.

        Uses the device info listed in testpmd and then parses the output.

        Returns:
            A list of devices.
        """
        dev_info: str = self.send_command("show device info all")
        dev_list: list[TestPmdDevice] = []
        for line in dev_info.split("\n"):
            if "device name:" in line.lower():
                dev_list.append(TestPmdDevice(line))
        return dev_list

    def wait_link_status_up(self, port_id: int) -> bool:
        """Wait until the link status on the given port is "up". Times out.

        Arguments:
            port_id: Port to check the link status on.

        Returns:
            Whether the link came up in time or not.
        """
        time_to_stop = time.time() + self._timeout
        port_info: str = ""
        while time.time() < time_to_stop:
            port_info = self.send_command(f"show port info {port_id}")
            if "Link status: up" in port_info:
                break
            time.sleep(0.5)
        else:
            self._logger.error(f"The link for port {port_id} did not come up in the given timeout.")
        return "Link status: up" in port_info

    def set_forward_mode(self, mode: TestPmdForwardingModes, verify: bool = True):
        """Set packet forwarding mode.

        Args:
            mode: The forwarding mode to use.
            verify: If :data:`True` the output of the command will be scanned in an attempt to
                verify that the forwarding mode was set to `mode` properly.

        Raises:
            InteractiveCommandExecutionError: If `verify` is :data:`True` and the forwarding mode
                fails to update.
        """
        set_fwd_output = self.send_command(f"set fwd {mode.value}")
        if f"Set {mode.value} packet forwarding mode" not in set_fwd_output:
            self._logger.debug(f"Failed to set fwd mode to {mode.value}:\n{set_fwd_output}")
            raise InteractiveCommandExecutionError(
                f"Test pmd failed to set fwd mode to {mode.value}"
            )

    def close(self) -> None:
        """Overrides :meth:`~.interactive_shell.close`."""
        self.send_command("quit", "")
        return super().close()

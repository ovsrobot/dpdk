# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2021 Intel Corporation
# Copyright(c) 2022-2023 University of New Hampshire
# Copyright(c) 2023 PANTHEON.tech s.r.o.
# Copyright(c) 2024 Arm Limited

"""Testbed configuration and test suite specification.

This package offers classes that hold real-time information about the testbed, hold test run
configuration describing the tested testbed and a loader function, :func:`load_config`, which loads
the YAML test run configuration file and validates it against the :class:`Configuration` Pydantic
dataclass model. The Pydantic model is also available as
:download:`JSON schema <conf_yaml_schema.json>`.

The YAML test run configuration file is parsed into a dictionary, parts of which are used throughout
this package. The allowed keys and types inside this dictionary map directly to the
:class:`Configuration` model, its fields and sub-models.

The test run configuration has two main sections:

    * The :class:`TestRunConfiguration` which defines what tests are going to be run
      and how DPDK will be built. It also references the testbed where these tests and DPDK
      are going to be run,
    * The nodes of the testbed are defined in the other section,
      a :class:`list` of :class:`NodeConfiguration` objects.

The real-time information about testbed is supposed to be gathered at runtime.

The classes defined in this package make heavy use of :mod:`pydantic.dataclasses`.
All of them use slots and are frozen:

    * Slots enables some optimizations, by pre-allocating space for the defined
      attributes in the underlying data structure,
    * Frozen makes the object immutable. This enables further optimizations,
      and makes it thread safe should we ever want to move in that direction.
"""

# pylama:ignore=W0611

from enum import Enum, auto, unique
from functools import cached_property
from pathlib import Path
from typing import Annotated, Literal, NamedTuple, Protocol

import yaml
from pydantic import (
    ConfigDict,
    Field,
    StringConstraints,
    TypeAdapter,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic.dataclasses import dataclass
from typing_extensions import Self

from framework.exception import ConfigurationError
from framework.utils import StrEnum

from .generated import CUSTOM_CONFIG_TYPES, TestSuitesConfigs
from .test_suite import TestSuiteConfig


@unique
class Architecture(StrEnum):
    r"""The supported architectures of :class:`~framework.testbed_model.node.Node`\s."""

    #:
    i686 = auto()
    #:
    x86_64 = auto()
    #:
    x86_32 = auto()
    #:
    arm64 = auto()
    #:
    ppc64le = auto()


@unique
class OS(StrEnum):
    r"""The supported operating systems of :class:`~framework.testbed_model.node.Node`\s."""

    #:
    linux = auto()
    #:
    freebsd = auto()
    #:
    windows = auto()


@unique
class CPUType(StrEnum):
    r"""The supported CPUs of :class:`~framework.testbed_model.node.Node`\s."""

    #:
    native = auto()
    #:
    armv8a = auto()
    #:
    dpaa2 = auto()
    #:
    thunderx = auto()
    #:
    xgene1 = auto()


@unique
class Compiler(StrEnum):
    r"""The supported compilers of :class:`~framework.testbed_model.node.Node`\s."""

    #:
    gcc = auto()
    #:
    clang = auto()
    #:
    icc = auto()
    #:
    msvc = auto()


@unique
class TrafficGeneratorType(str, Enum):
    """The supported traffic generators."""

    #:
    SCAPY = "SCAPY"


@dataclass(slots=True, frozen=True, kw_only=True, config=ConfigDict(extra="forbid"))
class HugepageConfiguration:
    r"""The hugepage configuration of :class:`~framework.testbed_model.node.Node`\s.

    Attributes:
        number_of: The number of hugepages to allocate.
        force_first_numa: If :data:`True`, the hugepages will be configured on the first NUMA node.
    """

    number_of: int
    force_first_numa: bool


PciAddress = Annotated[
    str, StringConstraints(pattern=r"^[\da-fA-F]{4}:[\da-fA-F]{2}:[\da-fA-F]{2}.\d:?\w*$")
]
"""A constrained string type representing a PCI address."""


@dataclass(slots=True, frozen=True, kw_only=True, config=ConfigDict(extra="forbid"))
class PortConfig:
    r"""The port configuration of :class:`~framework.testbed_model.node.Node`\s.

    Attributes:
        pci: The PCI address of the port.
        os_driver_for_dpdk: The operating system driver name for use with DPDK.
        os_driver: The operating system driver name when the operating system controls the port.
        peer_node: The :class:`~framework.testbed_model.node.Node` of the port
            connected to this port.
        peer_pci: The PCI address of the port connected to this port.
    """

    pci: PciAddress = Field(description="The local PCI address of the port.")
    os_driver_for_dpdk: str = Field(
        description="The driver that the kernel should bind this device to for DPDK to use it.",
        examples=["vfio-pci", "mlx5_core"],
    )
    os_driver: str = Field(
        description="The driver normally used by this port", examples=["i40e", "ice", "mlx5_core"]
    )
    peer_node: str = Field(description="The name of the peer node this port is connected to.")
    peer_pci: PciAddress = Field(
        description="The PCI address of the peer port this port is connected to."
    )


class TrafficGeneratorConfig(Protocol):
    """A protocol required to define traffic generator types.

    Attributes:
        type: The traffic generator type, the child class is required to define to be distinguished
            among others.
    """

    type: TrafficGeneratorType


@dataclass(slots=True, frozen=True, kw_only=True, config=ConfigDict(extra="forbid"))
class ScapyTrafficGeneratorConfig(TrafficGeneratorConfig):
    """Scapy traffic generator specific configuration."""

    type: Literal[TrafficGeneratorType.SCAPY]


TrafficGeneratorConfigTypes = Annotated[ScapyTrafficGeneratorConfig, Field(discriminator="type")]


LogicalCores = Annotated[
    str,
    StringConstraints(pattern=r"^(([0-9]+|([0-9]+-[0-9]+))(,([0-9]+|([0-9]+-[0-9]+)))*)?$"),
    Field(
        description="Comma-separated list of logical cores to use. "
        "An empty string means use all lcores.",
        examples=["1,2,3,4,5,18-22", "10-15"],
    ),
]


@dataclass(slots=True, frozen=True, kw_only=True, config=ConfigDict(extra="forbid"))
class NodeConfiguration:
    r"""The configuration of :class:`~framework.testbed_model.node.Node`\s.

    Attributes:
        name: The name of the :class:`~framework.testbed_model.node.Node`.
        hostname: The hostname of the :class:`~framework.testbed_model.node.Node`.
            Can be an IP or a domain name.
        user: The name of the user used to connect to
            the :class:`~framework.testbed_model.node.Node`.
        password: The password of the user. The use of passwords is heavily discouraged.
            Please use keys instead.
        arch: The architecture of the :class:`~framework.testbed_model.node.Node`.
        os: The operating system of the :class:`~framework.testbed_model.node.Node`.
        lcores: A comma delimited list of logical cores to use when running DPDK.
        use_first_core: If :data:`True`, the first logical core won't be used.
        hugepages: An optional hugepage configuration.
        ports: The ports that can be used in testing.
    """

    name: str = Field(description="A unique identifier for this node.")
    hostname: str = Field(description="The hostname or IP address of the node.")
    user: str = Field(description="The login user to use to connect to this node.")
    password: str | None = Field(
        default=None,
        description="The login password to use to connect to this node. "
        "SSH keys are STRONGLY preferred, use only as last resort.",
    )
    arch: Architecture
    os: OS
    lcores: LogicalCores = "1"
    use_first_core: bool = Field(
        default=False, description="DPDK won't use the first physical core if set to False."
    )
    hugepages: HugepageConfiguration | None = Field(None, alias="hugepages_2mb")
    ports: list[PortConfig] = Field(min_length=1)


@dataclass(slots=True, frozen=True, kw_only=True, config=ConfigDict(extra="forbid"))
class SutNodeConfiguration(NodeConfiguration):
    """:class:`~framework.testbed_model.sut_node.SutNode` specific configuration.

    Attributes:
        memory_channels: The number of memory channels to use when running DPDK.
    """

    memory_channels: int = Field(
        default=1, description="Number of memory channels to use when running DPDK."
    )


@dataclass(slots=True, frozen=True, kw_only=True, config=ConfigDict(extra="forbid"))
class TGNodeConfiguration(NodeConfiguration):
    """:class:`~framework.testbed_model.tg_node.TGNode` specific configuration.

    Attributes:
        traffic_generator: The configuration of the traffic generator present on the TG node.
    """

    traffic_generator: TrafficGeneratorConfigTypes


NodeConfigurationTypes = TGNodeConfiguration | SutNodeConfiguration
"""Union type for all the node configuration types."""


@dataclass(slots=True, frozen=True, config=ConfigDict(extra="forbid"))
class NodeInfo:
    """Supplemental node information.

    Attributes:
        os_name: The name of the running operating system of
            the :class:`~framework.testbed_model.node.Node`.
        os_version: The version of the running operating system of
            the :class:`~framework.testbed_model.node.Node`.
        kernel_version: The kernel version of the running operating system of
            the :class:`~framework.testbed_model.node.Node`.
    """

    os_name: str
    os_version: str
    kernel_version: str


@dataclass(frozen=True, kw_only=True, config=ConfigDict(extra="forbid"))
class BuildTargetConfiguration:
    """DPDK build configuration.

    The configuration used for building DPDK.

    Attributes:
        arch: The target architecture to build for.
        os: The target os to build for.
        cpu: The target CPU to build for.
        compiler: The compiler executable to use.
        compiler_wrapper: This string will be put in front of the compiler when
            executing the build. Useful for adding wrapper commands, such as ``ccache``.
    """

    arch: Architecture
    os: OS
    cpu: CPUType
    compiler: Compiler
    compiler_wrapper: str = ""

    @cached_property
    def name(self) -> str:
        """The name of the compiler."""
        return f"{self.arch}-{self.os}-{self.cpu}-{self.compiler}"


@dataclass(slots=True, frozen=True, kw_only=True, config=ConfigDict(extra="forbid"))
class BuildTargetInfo:
    """Various versions and other information about a build target.

    Attributes:
        dpdk_version: The DPDK version that was built.
        compiler_version: The version of the compiler used to build DPDK.
    """

    dpdk_version: str
    compiler_version: str


@dataclass(slots=True, frozen=True, kw_only=True, config=ConfigDict(extra="forbid"))
class TestRunSUTNodeConfiguration:
    """The SUT node configuration of a test run.

    Attributes:
        node_name: The SUT node to use in this test run.
        vdevs: The names of virtual devices to test.
    """

    node_name: str
    vdevs: list[str] = Field(default_factory=list)


@dataclass(slots=True, frozen=True, kw_only=True, config=ConfigDict(extra="forbid"))
class TestRunConfiguration:
    """The configuration of a test run.

    The configuration contains testbed information, what tests to execute
    and with what DPDK build.

    Attributes:
        build_targets: A list of DPDK builds to test.
        perf: Whether to run performance tests.
        func: Whether to run functional tests.
        skip_smoke_tests: Whether to skip smoke tests.
        test_suites: The names of test suites and/or test cases to execute.
        system_under_test_node: The SUT node configuration to use in this test run.
        traffic_generator_node: The TG node name to use in this test run.
    """

    build_targets: list[BuildTargetConfiguration]
    perf: bool = Field(description="Enable performance testing.")
    func: bool = Field(description="Enable functional testing.")
    skip_smoke_tests: bool = False
    test_suites: TestSuitesConfigs
    system_under_test_node: TestRunSUTNodeConfiguration
    traffic_generator_node: str


class TestRunWithNodesConfiguration(NamedTuple):
    """Tuple containing the configuration of the test run and its associated nodes."""

    #:
    test_run_config: TestRunConfiguration
    #:
    sut_node_config: SutNodeConfiguration
    #:
    tg_node_config: TGNodeConfiguration


@dataclass(frozen=True, kw_only=True)
class Configuration:
    """DTS testbed and test configuration.

    Attributes:
        test_runs: Test run configurations.
        nodes: Node configurations.
    """

    test_runs: list[TestRunConfiguration] = Field(min_length=1)
    nodes: list[NodeConfigurationTypes] = Field(min_length=1)

    @field_validator("nodes")
    @classmethod
    def validate_node_names(cls, nodes: list[NodeConfiguration]) -> list[NodeConfiguration]:
        """Validate that the node names are unique."""
        nodes_by_name: dict[str, int] = {}
        for node_no, node in enumerate(nodes):
            assert node.name not in nodes_by_name, (
                f"node {node_no} cannot have the same name as node {nodes_by_name[node.name]} "
                f"({node.name})"
            )
            nodes_by_name[node.name] = node_no

        return nodes

    @model_validator(mode="after")
    def validate_ports(self) -> Self:
        """Validate that the ports are all linked to valid ones."""
        port_links: dict[tuple[str, str], Literal[False] | tuple[int, int]] = {
            (node.name, port.pci): False for node in self.nodes for port in node.ports
        }

        for node_no, node in enumerate(self.nodes):
            for port_no, port in enumerate(node.ports):
                peer_port_identifier = (port.peer_node, port.peer_pci)
                peer_port = port_links.get(peer_port_identifier, None)
                assert peer_port is not None, (
                    "invalid peer port specified for " f"nodes.{node_no}.ports.{port_no}"
                )
                assert peer_port is False, (
                    f"the peer port specified for nodes.{node_no}.ports.{port_no} "
                    f"is already linked to nodes.{peer_port[0]}.ports.{peer_port[1]}"
                )
                port_links[peer_port_identifier] = (node_no, port_no)

        return self

    @cached_property
    def test_runs_with_nodes(self) -> list[TestRunWithNodesConfiguration]:
        """List test runs with the associated nodes."""
        test_runs_with_nodes = []

        for test_run_no, test_run in enumerate(self.test_runs):
            sut_node_name = test_run.system_under_test_node.node_name
            sut_node = next(filter(lambda n: n.name == sut_node_name, self.nodes), None)

            assert sut_node is not None, (
                f"test_runs.{test_run_no}.sut_node_config.node_name "
                f"({test_run.system_under_test_node.node_name}) is not a valid node name"
            )
            assert isinstance(sut_node, SutNodeConfiguration), (
                f"test_runs.{test_run_no}.sut_node_config.node_name is a valid node name, "
                "but it is not a valid SUT node"
            )

            tg_node_name = test_run.traffic_generator_node
            tg_node = next(filter(lambda n: n.name == tg_node_name, self.nodes), None)

            assert tg_node is not None, (
                f"test_runs.{test_run_no}.tg_node_name "
                f"({test_run.traffic_generator_node}) is not a valid node name"
            )
            assert isinstance(tg_node, TGNodeConfiguration), (
                f"test_runs.{test_run_no}.tg_node_name is a valid node name, "
                "but it is not a valid TG node"
            )

            test_runs_with_nodes.append(TestRunWithNodesConfiguration(test_run, sut_node, tg_node))

        return test_runs_with_nodes

    @model_validator(mode="after")
    def validate_test_runs_with_nodes(self) -> Self:
        """Validate the test runs to nodes associations.

        This validator relies on the cached property `test_runs_with_nodes` to run for the first
        time in this call, therefore triggering the assertions if needed.
        """
        if self.test_runs_with_nodes:
            pass
        return self


ConfigurationType = TypeAdapter(Configuration)


def load_config(config_file_path: Path) -> Configuration:
    """Load DTS test run configuration from a file.

    Load the YAML test run configuration file, validate it, and create a test run configuration
    object.

    The YAML test run configuration file is specified in the :option:`--config-file` command line
    argument or the :envvar:`DTS_CFG_FILE` environment variable.

    Args:
        config_file_path: The path to the YAML test run configuration file.

    Returns:
        The parsed test run configuration.

    Raises:
        ConfigurationError: If the supplied configuration file is invalid.
    """
    with open(config_file_path, "r") as f:
        config_data = yaml.safe_load(f)

    try:
        TestSuitesConfigs.fix_custom_config_annotations()
        return ConfigurationType.validate_python(config_data)
    except ValidationError as e:
        raise ConfigurationError("failed to load the supplied configuration") from e

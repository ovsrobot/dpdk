# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2023 PANTHEON.tech s.r.o.

"""Configuration dictionary contents specification.

These type definitions serve as documentation of the configuration dictionary contents.

The definitions use the built-in :class:`~typing.TypedDict` construct.
"""

from typing import TypedDict


class PortConfigDict(TypedDict):
    """Allowed keys and values."""

    #:
    pci: str
    #:
    os_driver_for_dpdk: str
    #:
    os_driver: str
    #:
    peer_node: str
    #:
    peer_pci: str


class TrafficGeneratorConfigDict(TypedDict):
    """Allowed keys and values."""

    #:
    type: str


class DPDKConfigDict(TypedDict):
    """Allowed keys and values."""

    #:
    memory_channels: int
    #:
    lcores: str


class HugepageConfigurationDict(TypedDict):
    """Allowed keys and values."""

    #:
    number_of: int
    #:
    force_first_numa: bool


class NodeConfigDict(TypedDict):
    """Allowed keys and values."""

    #:
    hugepages_2mb: HugepageConfigurationDict
    #:
    name: str
    #:
    hostname: str
    #:
    user: str
    #:
    password: str
    #:
    os: str
    #:
    ports: list[PortConfigDict]
    #:
    traffic_generator: TrafficGeneratorConfigDict
    #:
    dpdk_config: DPDKConfigDict


class BuildTargetConfigDict(TypedDict):
    """Allowed keys and values."""

    #:
    compiler: str
    #:
    compiler_wrapper: str


class TestSuiteConfigDict(TypedDict):
    """Allowed keys and values."""

    #:
    suite: str
    #:
    cases: list[str]


class TestRunSUTConfigDict(TypedDict):
    """Allowed keys and values."""

    #:
    node_name: str
    #:
    vdevs: list[str]


class TestRunConfigDict(TypedDict):
    """Allowed keys and values."""

    #:
    build_targets: list[BuildTargetConfigDict]
    #:
    perf: bool
    #:
    func: bool
    #:
    skip_smoke_tests: bool
    #:
    test_suites: TestSuiteConfigDict
    #:
    system_under_test_node: str
    #:
    traffic_generator_node: str
    #:
    vdevs: list[str]


class ConfigurationDict(TypedDict):
    """Allowed keys and values."""

    #:
    nodes: list[NodeConfigDict]
    #:
    test_runs: list[TestRunConfigDict]

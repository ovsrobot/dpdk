# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation
# Copyright(c) 2022-2023 PANTHEON.tech s.r.o.
# Copyright(c) 2022-2023 University of New Hampshire

"""
A node is a generic host that DTS connects to and manages.
"""

from framework.config import (
    Arch,
    BuildTargetConfiguration,
    ExecutionConfiguration,
    NodeConfiguration,
    create_arch,
)
from framework.logger import DTSLOG, getLogger
from framework.remote_session import OSSession, create_session

from .hw import (
    LogicalCore,
    LogicalCoreAmount,
    LogicalCoreList,
    LogicalCoreListFilter,
    lcore_filter,
)


class Node(object):
    """
    Basic class for node management. This class implements methods that
    manage a node, such as information gathering (of CPU/PCI/NIC) and
    environment setup.
    """

    main_session: OSSession
    config: NodeConfiguration
    name: str
    lcores: list[LogicalCore]
    _logger: DTSLOG
    _other_sessions: list[OSSession]
    _arch: Arch

    def __init__(self, node_config: NodeConfiguration):
        self.config = node_config
        self.name = node_config.name
        self._logger = getLogger(self.name)
        self.main_session = create_session(self.config, self.name, self._logger)

        self._get_remote_cpus()
        # filter the node lcores according to user config
        self.lcores = LogicalCoreListFilter(
            self.lcores, LogicalCoreList(self.config.lcores)
        ).filter()

        self._other_sessions = []
        self._arch = create_arch(self.config)

        self._logger.info(f"Created node: {self.name}")

    def set_up_execution(self, execution_config: ExecutionConfiguration) -> None:
        """
        Perform the execution setup that will be done for each execution
        this node is part of.
        """
        self._setup_hugepages()
        self._set_up_execution(execution_config)

    def _set_up_execution(self, execution_config: ExecutionConfiguration) -> None:
        """
        This method exists to be optionally overwritten by derived classes and
        is not decorated so that the derived class doesn't have to use the decorator.
        """

    def tear_down_execution(self) -> None:
        """
        Perform the execution teardown that will be done after each execution
        this node is part of concludes.
        """
        self._tear_down_execution()

    def _tear_down_execution(self) -> None:
        """
        This method exists to be optionally overwritten by derived classes and
        is not decorated so that the derived class doesn't have to use the decorator.
        """

    def set_up_build_target(
        self, build_target_config: BuildTargetConfiguration
    ) -> None:
        """
        Perform the build target setup that will be done for each build target
        tested on this node.
        """
        self._set_up_build_target(build_target_config)

    def _set_up_build_target(
        self, build_target_config: BuildTargetConfiguration
    ) -> None:
        """
        This method exists to be optionally overwritten by derived classes and
        is not decorated so that the derived class doesn't have to use the decorator.
        """

    def tear_down_build_target(self) -> None:
        """
        Perform the build target teardown that will be done after each build target
        tested on this node.
        """
        self._tear_down_build_target()

    def _tear_down_build_target(self) -> None:
        """
        This method exists to be optionally overwritten by derived classes and
        is not decorated so that the derived class doesn't have to use the decorator.
        """

    def create_session(self, name: str) -> OSSession:
        """
        Create and return a new OSSession tailored to the remote OS.
        """
        connection = create_session(
            self.config,
            name,
            getLogger(name, node=self.name),
        )
        self._other_sessions.append(connection)
        return connection

    def filter_lcores(
        self,
        filter_specifier: LogicalCoreAmount | LogicalCoreList,
        ascending: bool = True,
    ) -> list[LogicalCore]:
        """
        Filter the LogicalCores found on the Node according to specified rules:
        Use cores from the specified amount of sockets or from the specified socket ids.
        If sockets is specified, it takes precedence over socket_amount.
        From each of those sockets, use only cores_per_socket of cores.
        And for each core, use lcores_per_core of logical cores. Hypertheading
        must be enabled for this to take effect.
        If ascending is True, use cores with the lowest numerical id first
        and continue in ascending order. If False, start with the highest
        id and continue in descending order. This ordering affects which
        sockets to consider first as well.
        """
        self._logger.debug(f"Filtering {filter_specifier} from {self.lcores}.")
        return lcore_filter(
            self.lcores,
            filter_specifier,
            ascending,
        ).filter()

    def _get_remote_cpus(self) -> None:
        """
        Scan CPUs in the remote OS and store a list of LogicalCores.
        """
        self._logger.info("Getting CPU information.")
        self.lcores = self.main_session.get_remote_cpus(self.config.use_first_core)

    def _setup_hugepages(self):
        """
        Setup hugepages on the Node. Different architectures can supply different
        amounts of memory for hugepages and numa-based hugepage allocation may need
        to be considered.
        """
        self.main_session.setup_hugepages(
            self._arch.default_hugepage_memory, self._arch.hugepage_force_first_numa
        )

    def close(self) -> None:
        """
        Close all connections and free other resources.
        """
        if self.main_session:
            self.main_session.close()
        for session in self._other_sessions:
            session.close()
        self._logger.logger_exit()

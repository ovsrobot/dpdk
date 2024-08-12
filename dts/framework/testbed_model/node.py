# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation
# Copyright(c) 2022-2023 PANTHEON.tech s.r.o.
# Copyright(c) 2022-2023 University of New Hampshire
# Copyright(c) 2024 Arm Limited

"""Common functionality for node management.

A node is any host/server DTS connects to.

The base class, :class:`Node`, provides features common to all nodes and is supposed
to be extended by subclasses with features specific to each node type.
The :func:`~Node.skip_setup` decorator can be used without subclassing.
"""

import os
import tarfile
from abc import ABC
from ipaddress import IPv4Interface, IPv6Interface
from pathlib import PurePath
from typing import Any, Callable, Union

from framework.config import (
    OS,
    BuildTargetConfiguration,
    NodeConfiguration,
    TestRunConfiguration,
)
from framework.exception import ConfigurationError
from framework.logger import DTSLogger, get_dts_logger
from framework.settings import SETTINGS

from .cpu import (
    LogicalCore,
    LogicalCoreCount,
    LogicalCoreList,
    LogicalCoreListFilter,
    lcore_filter,
)
from .linux_session import LinuxSession
from .os_session import OSSession
from .port import Port


class Node(ABC):
    """The base class for node management.

    It shouldn't be instantiated, but rather subclassed.
    It implements common methods to manage any node:

        * Connection to the node,
        * Hugepages setup.

    Attributes:
        main_session: The primary OS-aware remote session used to communicate with the node.
        config: The node configuration.
        name: The name of the node.
        lcores: The list of logical cores that DTS can use on the node.
            It's derived from logical cores present on the node and the test run configuration.
        ports: The ports of this node specified in the test run configuration.
    """

    main_session: OSSession
    config: NodeConfiguration
    name: str
    lcores: list[LogicalCore]
    ports: list[Port]
    _logger: DTSLogger
    _remote_tmp_dir: PurePath
    __remote_dpdk_dir: PurePath | None
    _other_sessions: list[OSSession]
    _test_run_config: TestRunConfiguration
    _path_to_devbind_script: PurePath | None

    def __init__(self, node_config: NodeConfiguration):
        """Connect to the node and gather info during initialization.

        Extra gathered information:

        * The list of available logical CPUs. This is then filtered by
          the ``lcores`` configuration in the YAML test run configuration file,
        * Information about ports from the YAML test run configuration file.

        Args:
            node_config: The node's test run configuration.
        """
        self.config = node_config
        self.name = node_config.name
        self._logger = get_dts_logger(self.name)
        self.main_session = create_session(self.config, self.name, self._logger)

        self._logger.info(f"Connected to node: {self.name}")

        self._get_remote_cpus()
        # filter the node lcores according to the test run configuration
        self.lcores = LogicalCoreListFilter(
            self.lcores, LogicalCoreList(self.config.lcores)
        ).filter()

        self._other_sessions = []
        self._init_ports()
        self._remote_tmp_dir = self.main_session.get_remote_tmp_dir()
        self.__remote_dpdk_dir = None
        self._path_to_devbind_script = None

    def _init_ports(self) -> None:
        self.ports = [Port(self.name, port_config) for port_config in self.config.ports]
        self.main_session.update_ports(self.ports)
        for port in self.ports:
            self.configure_port_state(port)

    def _guess_dpdk_remote_dir(self) -> PurePath:
        return self.main_session.guess_dpdk_remote_dir(self._remote_tmp_dir)

    @property
    def _remote_dpdk_dir(self) -> PurePath:
        """The remote DPDK dir.

        This internal property should be set after extracting the DPDK tarball. If it's not set,
        that implies the DPDK setup step has been skipped, in which case we can guess where
        a previous build was located.
        """
        if self.__remote_dpdk_dir is None:
            self.__remote_dpdk_dir = self._guess_dpdk_remote_dir()
        return self.__remote_dpdk_dir

    @_remote_dpdk_dir.setter
    def _remote_dpdk_dir(self, value: PurePath) -> None:
        self.__remote_dpdk_dir = value

    @property
    def path_to_devbind_script(self) -> PurePath:
        """The path to the dpdk-devbind.py script on the node."""
        if self._path_to_devbind_script is None:
            self._path_to_devbind_script = self.main_session.join_remote_path(
                self._remote_dpdk_dir, "usertools", "dpdk-devbind.py"
            )
        return self._path_to_devbind_script

    def set_up_test_run(self, test_run_config: TestRunConfiguration) -> None:
        """Test run setup steps.

        Configure hugepages on all DTS node types. Additional steps can be added by
        extending the method in subclasses with the use of super().

        Args:
            test_run_config: A test run configuration according to which
                the setup steps will be taken.
        """
        self._setup_hugepages()

    def tear_down_test_run(self) -> None:
        """Test run teardown steps.

        There are currently no common execution teardown steps common to all DTS node types.
        Additional steps can be added by extending the method in subclasses with the use of super().
        """

    def set_up_build_target(self, build_target_config: BuildTargetConfiguration) -> None:
        """Set up DPDK the node and bind ports.

        DPDK setup includes setting all internals needed for the build, the copying of DPDK tarball
        and then building DPDK. The drivers are bound to those that DPDK needs.

        Args:
            build_target_config: The build target test run configuration according to which
                the setup steps will be taken.
        """
        self._copy_dpdk_tarball()
        self.bind_ports_to_driver()

    def tear_down_build_target(self) -> None:
        """Reset DPDK variables and bind port driver to the OS driver."""
        self.__remote_dpdk_dir = None
        self.bind_ports_to_driver(for_dpdk=False)

    def create_session(self, name: str) -> OSSession:
        """Create and return a new OS-aware remote session.

        The returned session won't be used by the node creating it. The session must be used by
        the caller. The session will be maintained for the entire lifecycle of the node object,
        at the end of which the session will be cleaned up automatically.

        Note:
            Any number of these supplementary sessions may be created.

        Args:
            name: The name of the session.

        Returns:
            A new OS-aware remote session.
        """
        session_name = f"{self.name} {name}"
        connection = create_session(
            self.config,
            session_name,
            get_dts_logger(session_name),
        )
        self._other_sessions.append(connection)
        return connection

    def filter_lcores(
        self,
        filter_specifier: LogicalCoreCount | LogicalCoreList,
        ascending: bool = True,
    ) -> list[LogicalCore]:
        """Filter the node's logical cores that DTS can use.

        Logical cores that DTS can use are the ones that are present on the node, but filtered
        according to the test run configuration. The `filter_specifier` will filter cores from
        those logical cores.

        Args:
            filter_specifier: Two different filters can be used, one that specifies the number
                of logical cores per core, cores per socket and the number of sockets,
                and another one that specifies a logical core list.
            ascending: If :data:`True`, use cores with the lowest numerical id first and continue
                in ascending order. If :data:`False`, start with the highest id and continue
                in descending order. This ordering affects which sockets to consider first as well.

        Returns:
            The filtered logical cores.
        """
        self._logger.debug(f"Filtering {filter_specifier} from {self.lcores}.")
        return lcore_filter(
            self.lcores,
            filter_specifier,
            ascending,
        ).filter()

    def _get_remote_cpus(self) -> None:
        """Scan CPUs in the remote OS and store a list of LogicalCores."""
        self._logger.info("Getting CPU information.")
        self.lcores = self.main_session.get_remote_cpus(self.config.use_first_core)

    def _setup_hugepages(self) -> None:
        """Setup hugepages on the node.

        Configure the hugepages only if they're specified in the node's test run configuration.
        """
        if self.config.hugepages:
            self.main_session.setup_hugepages(
                self.config.hugepages.number_of,
                self.main_session.hugepage_size,
                self.config.hugepages.force_first_numa,
            )

    def configure_port_state(self, port: Port, enable: bool = True) -> None:
        """Enable/disable `port`.

        Args:
            port: The port to enable/disable.
            enable: :data:`True` to enable, :data:`False` to disable.
        """
        self.main_session.configure_port_state(port, enable)

    def configure_port_ip_address(
        self,
        address: Union[IPv4Interface, IPv6Interface],
        port: Port,
        delete: bool = False,
    ) -> None:
        """Add an IP address to `port` on this node.

        Args:
            address: The IP address with mask in CIDR format. Can be either IPv4 or IPv6.
            port: The port to which to add the address.
            delete: If :data:`True`, will delete the address from the port instead of adding it.
        """
        self.main_session.configure_port_ip_address(address, port, delete)

    def close(self) -> None:
        """Close all connections and free other resources."""
        if self.main_session:
            self.main_session.close()
        for session in self._other_sessions:
            session.close()

    @staticmethod
    def skip_setup(func: Callable[..., Any]) -> Callable[..., Any]:
        """Skip the decorated function.

        The :option:`--skip-setup` command line argument and the :envvar:`DTS_SKIP_SETUP`
        environment variable enable the decorator.
        """
        if SETTINGS.skip_setup:
            return lambda *args: None
        else:
            return func

    @skip_setup
    def _copy_dpdk_tarball(self) -> None:
        """Copy to and extract DPDK tarball on the node."""
        self._logger.info(f"Copying DPDK tarball to {self.name}.")
        self.main_session.copy_to(SETTINGS.dpdk_tarball_path, self._remote_tmp_dir)

        # construct remote tarball path
        # the basename is the same on local host and on remote Node
        remote_tarball_path = self.main_session.join_remote_path(
            self._remote_tmp_dir, os.path.basename(SETTINGS.dpdk_tarball_path)
        )

        # construct remote path after extracting
        with tarfile.open(SETTINGS.dpdk_tarball_path) as dpdk_tar:
            dpdk_top_dir = dpdk_tar.getnames()[0]
        self._remote_dpdk_dir = self.main_session.join_remote_path(
            self._remote_tmp_dir, dpdk_top_dir
        )

        self._logger.info(
            f"Extracting DPDK tarball on {self.name}: "
            f"'{remote_tarball_path}' into '{self._remote_dpdk_dir}'."
        )
        # clean remote path where we're extracting
        self.main_session.remove_remote_dir(self._remote_dpdk_dir)

        # then extract to remote path
        self.main_session.extract_remote_tarball(remote_tarball_path, self._remote_dpdk_dir)

    def bind_ports_to_driver(self, for_dpdk: bool = True) -> None:
        """Bind all ports on the node to a driver.

        Args:
            for_dpdk: If :data:`True`, binds ports to os_driver_for_dpdk.
                If :data:`False`, binds to os_driver.
        """
        for port in self.ports:
            driver = port.os_driver_for_dpdk if for_dpdk else port.os_driver
            self.main_session.send_command(
                f"{self.path_to_devbind_script} -b {driver} --force {port.pci}",
                privileged=True,
                verify=True,
            )


def create_session(node_config: NodeConfiguration, name: str, logger: DTSLogger) -> OSSession:
    """Factory for OS-aware sessions.

    Args:
        node_config: The test run configuration of the node to connect to.
        name: The name of the session.
        logger: The logger instance this session will use.
    """
    match node_config.os:
        case OS.linux:
            return LinuxSession(node_config, name, logger)
        case _:
            raise ConfigurationError(f"Unsupported OS {node_config.os}")

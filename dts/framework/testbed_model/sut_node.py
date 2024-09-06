# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation
# Copyright(c) 2023 PANTHEON.tech s.r.o.
# Copyright(c) 2023 University of New Hampshire
# Copyright(c) 2024 Arm Limited

"""System under test (DPDK + hardware) node.

A system under test (SUT) is the combination of DPDK
and the hardware we're testing with DPDK (NICs, crypto and other devices).
An SUT node is where this SUT runs.
"""


import os
import time
from pathlib import PurePath

from framework.config import (
    DPDKBuildConfiguration,
    DPDKBuildInfo,
    DPDKLocation,
    NodeInfo,
    SutNodeConfiguration,
    TestRunConfiguration,
)
from framework.exception import RemoteFileNotFoundError
from framework.params.eal import EalParams
from framework.remote_session.remote_session import CommandResult
from framework.utils import MesonArgs

from .node import Node
from .os_session import OSSession
from .virtual_device import VirtualDevice


class SutNode(Node):
    """The system under test node.

    The SUT node extends :class:`Node` with DPDK specific features:

        * Managing DPDK source tree on the remote SUT,
        * Building the DPDK from source or using a pre-built version,
        * Gathering of DPDK build info,
        * The running of DPDK apps, interactively or one-time execution,
        * DPDK apps cleanup.

    The :option:`--tarball` command line argument, :envvar:`DTS_DPDK_TARBALL` environment variable
    and `tarball` inside `dpdk_build` from configuration, set the path to the DPDK tarball.

    The :option:`--dpdk-tree` command line argument, :envvar:`DTS_DPDK_TREE` environment variable
    and `dpdk-tree` inside `dpdk_build` from configuration, set the path to the DPDK tree.

    The :option:`--remote-source` command line argument, :envvar:`DTS_REMOTE_SOURCE` environment
    variable and `remote` inside `dpdk_build` from configuration, set when the `dpdk_tree` or
    `tarball` is located on the SUT node.

    The :option:`--build-dir` command line argument, :envvar:`DTS_BUILD_DIR` environment
    variable and `dir_name` inside `dpdk_build` from configuration, set a directory name,
    which would be located in the `dpdk_tree` or `tarball`.

    Building DPDK from source uses `build` configuration inside `dpdk_build` of configuration.

    Attributes:
        config: The SUT node configuration.
        virtual_devices: The virtual devices used on the node.
    """

    config: SutNodeConfiguration
    virtual_devices: list[VirtualDevice]
    dpdk_prefix_list: list[str]
    dpdk_timestamp: str
    _env_vars: dict
    _remote_tmp_dir: PurePath
    __remote_dpdk_tree_path: str | PurePath | None
    _remote_dpdk_build_dir: PurePath | None
    _app_compile_timeout: float
    _dpdk_kill_session: OSSession | None
    _dpdk_version: str | None
    _node_info: NodeInfo | None
    _compiler_version: str | None
    _path_to_devbind_script: PurePath | None

    def __init__(self, node_config: SutNodeConfiguration):
        """Extend the constructor with SUT node specifics.

        Args:
            node_config: The SUT node's test run configuration.
        """
        super().__init__(node_config)
        self.virtual_devices = []
        self.dpdk_prefix_list = []
        self._env_vars = {}
        self._remote_tmp_dir = self.main_session.get_remote_tmp_dir()
        self.__remote_dpdk_tree_path = None
        self._remote_dpdk_build_dir = None
        self._app_compile_timeout = 90
        self._dpdk_kill_session = None
        self.dpdk_timestamp = (
            f"{str(os.getpid())}_{time.strftime('%Y%m%d%H%M%S', time.localtime())}"
        )
        self._dpdk_version = None
        self._node_info = None
        self._compiler_version = None
        self._path_to_devbind_script = None
        self._logger.info(f"Created node: {self.name}")

    @property
    def _remote_dpdk_tree_path(self) -> str | PurePath:
        """The remote DPDK tree path."""
        if self.__remote_dpdk_tree_path:
            return self.__remote_dpdk_tree_path

        self._logger.warning(
            "Failed to get remote dpdk tree path because we don't know the "
            "location on the SUT node."
        )
        return ""

    @property
    def remote_dpdk_build_dir(self) -> str | PurePath:
        """The remote DPDK build dir path."""
        if self._remote_dpdk_build_dir:
            return self._remote_dpdk_build_dir

        self._logger.warning(
            "Failed to get remote dpdk build dir because we don't know the "
            "location on the SUT node."
        )
        return ""

    @property
    def dpdk_version(self) -> str | None:
        """Last built DPDK version."""
        if self._dpdk_version is None:
            self._dpdk_version = self.main_session.get_dpdk_version(self._remote_dpdk_tree_path)
        return self._dpdk_version

    @property
    def node_info(self) -> NodeInfo:
        """Additional node information."""
        if self._node_info is None:
            self._node_info = self.main_session.get_node_info()
        return self._node_info

    @property
    def compiler_version(self) -> str | None:
        """The node's compiler version."""
        return self._compiler_version

    @compiler_version.setter
    def compiler_version(self, value: str) -> None:
        """Set the compiler version used on the SUT.

        Args:
            value: The node's compiler version.
        """
        self._compiler_version = value

    @property
    def path_to_devbind_script(self) -> PurePath | str:
        """The path to the dpdk-devbind.py script on the node."""
        if self._path_to_devbind_script is None:
            self._path_to_devbind_script = self.main_session.join_remote_path(
                self._remote_dpdk_tree_path, "usertools", "dpdk-devbind.py"
            )
        return self._path_to_devbind_script

    def get_dpdk_build_info(self) -> DPDKBuildInfo:
        """Get additional DPDK build information.

        Returns:
            The DPDK build information,
        """
        return DPDKBuildInfo(dpdk_version=self.dpdk_version, compiler_version=self.compiler_version)

    def set_up_test_run(
        self, test_run_config: TestRunConfiguration, dpdk_location: DPDKLocation
    ) -> None:
        """Extend the test run setup with vdev config and DPDK build set up.

        This method extends the setup process by configuring virtual devices and preparing the DPDK
        environment based on the provided configuration.

        Args:
            test_run_config: A test run configuration according to which
                the setup steps will be taken.
            dpdk_location: The target source of the DPDK tree.
        """
        super().set_up_test_run(test_run_config, dpdk_location)
        for vdev in test_run_config.vdevs:
            self.virtual_devices.append(VirtualDevice(vdev))
        self._set_up_dpdk(dpdk_location, test_run_config.dpdk_build_config)

    def tear_down_test_run(self) -> None:
        """Extend the test run teardown with virtual device teardown and DPDK teardown."""
        super().tear_down_test_run()
        self.virtual_devices = []
        self._tear_down_dpdk()

    def _set_up_dpdk(
        self, dpdk_location: DPDKLocation, dpdk_build_config: DPDKBuildConfiguration | None
    ) -> None:
        """Set up DPDK the SUT node and bind ports.

        DPDK setup includes setting all internals needed for the build, the copying of DPDK
        sources and then building DPDK or used the exist ones from the `dpdk_location`. The drivers
        are bound to those that DPDK needs.

        Args:
            dpdk_location: The target source of the DPDK tree.
            dpdk_build_config: The DPDK build test run configuration according to which
                the setup steps will be taken.
        """
        self._set_remote_dpdk_tree_path(dpdk_location)
        if not self._remote_dpdk_tree_path:
            if dpdk_location.dpdk_tree:
                self._copy_dpdk_tree(dpdk_location.dpdk_tree)
            elif dpdk_location.tarball:
                self._prepare_and_extract_dpdk_tarball(dpdk_location.tarball, dpdk_location.remote)

        self._set_remote_dpdk_build_dir(dpdk_location.build_dir)
        if not self.remote_dpdk_build_dir and dpdk_build_config:
            self._configure_dpdk_build(dpdk_build_config)
            self._build_dpdk()

        self.bind_ports_to_driver()

    def _tear_down_dpdk(self) -> None:
        """Reset DPDK variables and bind port driver to the OS driver."""
        self._env_vars = {}
        self.__remote_dpdk_tree_path = None
        self._remote_dpdk_build_dir = None
        self._dpdk_version = None
        self._compiler_version = None
        self.bind_ports_to_driver(for_dpdk=False)

    def _set_remote_dpdk_tree_path(self, dpdk_location: DPDKLocation):
        """Set the path to the remote DPDK source tree based on the provided DPDK location.

        Verifies DPDK source tree existence on the SUT node and sets the `_remote_dpdk_tree_path`
            property.

        Args:
            dpdk_location: The target source of the DPDK tree.

        Raises:
            RemoteFileNotFoundError: If the DPDK source tree is expected to be on the SUT node but
                is not found.
        """
        if dpdk_location.remote and dpdk_location.dpdk_tree:
            if self.main_session.remote_path_exists(dpdk_location.dpdk_tree):
                self.__remote_dpdk_tree_path = PurePath(dpdk_location.dpdk_tree)
            else:
                raise RemoteFileNotFoundError(
                    f"Remote DPDK source tree '{dpdk_location.dpdk_tree}' not found in SUT node."
                )

    def _copy_dpdk_tree(self, dpdk_tree_path: str) -> None:
        """Copy the DPDK source tree to the SUT.

        Args:
            dpdk_tree_path: The path to DPDK source tree on local filesystem.
        """
        self._logger.info(
            f"Copying DPDK source tree to SUT: '{dpdk_tree_path}' into '{self._remote_tmp_dir}'."
        )
        self.main_session.copy_dir_to(dpdk_tree_path, self._remote_tmp_dir, exclude=".git")

        self.__remote_dpdk_tree_path = self.main_session.join_remote_path(
            self._remote_tmp_dir, PurePath(dpdk_tree_path).name
        )

    def _prepare_and_extract_dpdk_tarball(self, dpdk_tarball: str, remote: bool) -> None:
        """Ensure the DPDK tarball is available on the SUT node and extract it.

        This method ensures that the DPDK source tree tarball is available on the
        SUT node. If the `dpdk_tarball` is local, it is copied to the SUT node. If the
        `dpdk_tarball` is already on the SUT node, it verifies its existence.
        The `dpdk_tarball` is then extracted on the SUT node.

        This method sets the `_remote_dpdk_tree_path` property to the path of the
        extracted DPDK tree on the SUT node.

        Args:
            dpdk_tarball: The path to the DPDK tarball, either locally or on the SUT node.
            remote: Indicates whether the `dpdk_tarball` is already on the SUT node.

        Raises:
            RemoteFileNotFoundError: If the `dpdk_tarball` is expected to be on the SUT node but
                is not found.
        """
        if remote:
            if not self.main_session.remote_path_exists(dpdk_tarball):
                raise RemoteFileNotFoundError(
                    f"Remote DPDK tarball '{dpdk_tarball}' not found in SUT."
                )

            remote_tarball_path = PurePath(dpdk_tarball)
        else:
            self._logger.info(
                f"Copying DPDK tarball to SUT: '{dpdk_tarball}' into '{self._remote_tmp_dir}'."
            )
            self.main_session.copy_to(dpdk_tarball, self._remote_tmp_dir)

            remote_tarball_path = self.main_session.join_remote_path(
                self._remote_tmp_dir, PurePath(dpdk_tarball).name
            )

        tarball_top_dir = self.main_session.get_tarball_top_dir(remote_tarball_path)
        self.__remote_dpdk_tree_path = self.main_session.join_remote_path(
            PurePath(remote_tarball_path).parent,
            tarball_top_dir or PurePath(remote_tarball_path).stem,
        )

        self._logger.info(
            "Extracting DPDK tarball on SUT: "
            f"'{remote_tarball_path}' into '{self._remote_dpdk_tree_path}'."
        )
        self.main_session.extract_remote_tarball(
            remote_tarball_path,
            self._remote_dpdk_tree_path,
        )

    def _set_remote_dpdk_build_dir(self, build_dir: str | None):
        """Set the `remote_dpdk_build_dir` on the SUT.

        Args:
            build_dir: A directory name, which is located inside `_remote_dpdk_tree_path`.

        Raises:
            RemoteFileNotFoundError: If the `build_dir` does not exist on the SUT node.
        """
        if build_dir:
            remote_dpdk_build_dir = self.main_session.join_remote_path(
                self._remote_dpdk_tree_path, build_dir
            )
            if not self.main_session.remote_path_exists(remote_dpdk_build_dir):
                raise RemoteFileNotFoundError(
                    f"Remote DPDK build dir '{remote_dpdk_build_dir}' not found in SUT node."
                )

            self._remote_dpdk_build_dir = PurePath(remote_dpdk_build_dir)

    def _configure_dpdk_build(self, dpdk_build_config: DPDKBuildConfiguration) -> None:
        """Populate common environment variables and set the DPDK build related properties.

        This method sets `compiler_version` for additional information and `remote_dpdk_build_dir`
        from DPDK build config name.

        Args:
            dpdk_build_config: A DPDK build configuration to test.
        """
        self._env_vars = {}
        self._env_vars.update(self.main_session.get_dpdk_build_env_vars(dpdk_build_config.arch))
        self._env_vars["CC"] = dpdk_build_config.compiler.name
        if dpdk_build_config.compiler_wrapper:
            self._env_vars[
                "CC"
            ] = f"'{dpdk_build_config.compiler_wrapper} {dpdk_build_config.compiler.name}'"

        self.compiler_version = self.main_session.get_compiler_version(
            dpdk_build_config.compiler.name
        )

        self._remote_dpdk_build_dir = self.main_session.join_remote_path(
            self._remote_dpdk_tree_path, dpdk_build_config.name
        )

    def _build_dpdk(self) -> None:
        """Build DPDK.

        Uses the already configured DPDK build configuration. Assumes that the
        `_remote_dpdk_tree_path` has already been sets on the SUT node.
        """
        self.main_session.build_dpdk(
            self._env_vars,
            MesonArgs(default_library="static", enable_kmods=True, libdir="lib"),
            self._remote_dpdk_tree_path,
            self.remote_dpdk_build_dir,
        )

    def build_dpdk_app(self, app_name: str, **meson_dpdk_args: str | bool) -> PurePath:
        """Build one or all DPDK apps.

        Requires DPDK to be already built on the SUT node.

        Args:
            app_name: The name of the DPDK app to build.
                When `app_name` is ``all``, build all example apps.
            meson_dpdk_args: The arguments found in ``meson_options.txt`` in root DPDK directory.
                Do not use ``-D`` with them.

        Returns:
            The directory path of the built app. If building all apps, return
            the path to the examples directory (where all apps reside).
        """
        self.main_session.build_dpdk(
            self._env_vars,
            MesonArgs(examples=app_name, **meson_dpdk_args),  # type: ignore [arg-type]
            # ^^ https://github.com/python/mypy/issues/11583
            self._remote_dpdk_tree_path,
            self.remote_dpdk_build_dir,
            rebuild=True,
            timeout=self._app_compile_timeout,
        )

        if app_name == "all":
            return self.main_session.join_remote_path(self.remote_dpdk_build_dir, "examples")
        return self.main_session.join_remote_path(
            self.remote_dpdk_build_dir, "examples", f"dpdk-{app_name}"
        )

    def kill_cleanup_dpdk_apps(self) -> None:
        """Kill all dpdk applications on the SUT, then clean up hugepages."""
        if self._dpdk_kill_session and self._dpdk_kill_session.is_alive():
            # we can use the session if it exists and responds
            self._dpdk_kill_session.kill_cleanup_dpdk_apps(self.dpdk_prefix_list)
        else:
            # otherwise, we need to (re)create it
            self._dpdk_kill_session = self.create_session("dpdk_kill")
        self.dpdk_prefix_list = []

    def run_dpdk_app(
        self, app_path: PurePath, eal_params: EalParams, timeout: float = 30
    ) -> CommandResult:
        """Run DPDK application on the remote node.

        The application is not run interactively - the command that starts the application
        is executed and then the call waits for it to finish execution.

        Args:
            app_path: The remote path to the DPDK application.
            eal_params: EAL parameters to run the DPDK application with.
            timeout: Wait at most this long in seconds for `command` execution to complete.

        Returns:
            The result of the DPDK app execution.
        """
        return self.main_session.send_command(
            f"{app_path} {eal_params}", timeout, privileged=True, verify=True
        )

    def configure_ipv4_forwarding(self, enable: bool) -> None:
        """Enable/disable IPv4 forwarding on the node.

        Args:
            enable: If :data:`True`, enable the forwarding, otherwise disable it.
        """
        self.main_session.configure_ipv4_forwarding(enable)

    def bind_ports_to_driver(self, for_dpdk: bool = True) -> None:
        """Bind all ports on the SUT to a driver.

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

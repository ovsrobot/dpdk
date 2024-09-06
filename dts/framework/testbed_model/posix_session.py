# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2023 PANTHEON.tech s.r.o.
# Copyright(c) 2023 University of New Hampshire

"""POSIX compliant OS translator.

Translates OS-unaware calls into POSIX compliant calls/utilities. POSIX is a set of standards
for portability between Unix operating systems which not all Linux distributions
(or the tools most frequently bundled with said distributions) adhere to. Most of Linux
distributions are mostly compliant though.
This intermediate module implements the common parts of mostly POSIX compliant distributions.
"""

import re
from collections.abc import Iterable
from pathlib import Path, PurePath, PurePosixPath

from framework.config import Architecture, NodeInfo
from framework.exception import DPDKBuildError, RemoteCommandExecutionError
from framework.settings import SETTINGS
from framework.utils import (
    MesonArgs,
    TarCompressionFormat,
    create_tarball,
    ensure_list_of_strings,
    extract_tarball,
)

from .os_session import OSSession


class PosixSession(OSSession):
    """An intermediary class implementing the POSIX standard."""

    @staticmethod
    def combine_short_options(**opts: bool) -> str:
        """Combine shell options into one argument.

        These are options such as ``-x``, ``-v``, ``-f`` which are combined into ``-xvf``.

        Args:
            opts: The keys are option names (usually one letter) and the bool values indicate
                whether to include the option in the resulting argument.

        Returns:
            The options combined into one argument.
        """
        ret_opts = ""
        for opt, include in opts.items():
            if include:
                ret_opts = f"{ret_opts}{opt}"

        if ret_opts:
            ret_opts = f" -{ret_opts}"

        return ret_opts

    def guess_dpdk_remote_dir(self, remote_dir: str | PurePath) -> PurePosixPath:
        """Overrides :meth:`~.os_session.OSSession.guess_dpdk_remote_dir`."""
        remote_guess = self.join_remote_path(remote_dir, "dpdk-*")
        result = self.send_command(f"ls -d {remote_guess} | tail -1")
        return PurePosixPath(result.stdout)

    def get_remote_tmp_dir(self) -> PurePosixPath:
        """Overrides :meth:`~.os_session.OSSession.get_remote_tmp_dir`."""
        return PurePosixPath("/tmp")

    def get_dpdk_build_env_vars(self, arch: Architecture) -> dict:
        """Overrides :meth:`~.os_session.OSSession.get_dpdk_build_env_vars`.

        Supported architecture: ``i686``.
        """
        env_vars = {}
        if arch == Architecture.i686:
            # find the pkg-config path and store it in PKG_CONFIG_LIBDIR
            out = self.send_command("find /usr -type d -name pkgconfig")
            pkg_path = ""
            res_path = out.stdout.split("\r\n")
            for cur_path in res_path:
                if "i386" in cur_path:
                    pkg_path = cur_path
                    break
            assert pkg_path != "", "i386 pkg-config path not found"

            env_vars["CFLAGS"] = "-m32"
            env_vars["PKG_CONFIG_LIBDIR"] = pkg_path

        return env_vars

    def join_remote_path(self, *args: str | PurePath) -> PurePosixPath:
        """Overrides :meth:`~.os_session.OSSession.join_remote_path`."""
        return PurePosixPath(*args)

    def remote_path_exists(self, remote_path: str | PurePath) -> bool:
        """Overrides :meth:`~.os_session.OSSession.remote_path_exists`."""
        result = self.send_command(f"test -e {remote_path}")
        return not result.return_code

    def copy_from(
        self, source_file: str | PurePath, destination_dir: str | Path, force: bool = SETTINGS.force
    ) -> None:
        """Overrides :meth:`~.os_session.OSSession.copy_from`."""
        if force:
            Path(destination_dir, PurePath(source_file).name).unlink(missing_ok=True)

        self.remote_session.copy_from(source_file, destination_dir)

    def copy_to(
        self, source_file: str | Path, destination_dir: str | PurePath, force: bool = SETTINGS.force
    ) -> None:
        """Overrides :meth:`~.os_session.OSSession.copy_to`."""
        if force:
            self.remove_remote_file(PurePath(destination_dir, Path(source_file).name))

        self.remote_session.copy_to(source_file, destination_dir)

    def copy_dir_from(
        self,
        source_dir: str | PurePath,
        destination_dir: str | Path,
        compress_format: TarCompressionFormat = TarCompressionFormat.none,
        exclude: str | list[str] | None = None,
        force: bool = SETTINGS.force,
    ) -> None:
        """Overrides :meth:`~.os_session.OSSession.copy_dir_from`."""
        tarball_name = f"{PurePath(source_dir).name}{compress_format.extension}"
        remote_tarball_path = self.join_remote_path(PurePath(source_dir).parent, tarball_name)
        self.create_remote_tarball(source_dir, compress_format, exclude)

        self.copy_from(remote_tarball_path, destination_dir, force)
        self.remove_remote_file(remote_tarball_path)

        tarball_path = Path(destination_dir, tarball_name)
        extract_tarball(tarball_path)
        tarball_path.unlink()

    def copy_dir_to(
        self,
        source_dir: str | Path,
        destination_dir: str | PurePath,
        compress_format: TarCompressionFormat = TarCompressionFormat.none,
        exclude: str | list[str] | None = None,
        force: bool = SETTINGS.force,
    ) -> None:
        """Overrides :meth:`~.os_session.OSSession.copy_dir_to`."""
        source_dir_name = Path(source_dir).name
        tar_name = f"{source_dir_name}{compress_format.extension}"
        tar_path = Path(Path(source_dir).parent, tar_name)

        create_tarball(source_dir, compress_format, arcname=source_dir_name, exclude=exclude)
        self.copy_to(tar_path, destination_dir, force)
        tar_path.unlink()

        remote_tar_path = self.join_remote_path(destination_dir, tar_name)
        self.extract_remote_tarball(remote_tar_path)
        self.remove_remote_file(remote_tar_path)

    def remove_remote_file(self, remote_file_path: str | PurePath, force: bool = True) -> None:
        """Overrides :meth:`~.os_session.OSSession.remove_remote_dir`."""
        opts = PosixSession.combine_short_options(f=force)
        self.send_command(f"rm{opts} {remote_file_path}")

    def remove_remote_dir(
        self,
        remote_dir_path: str | PurePath,
        recursive: bool = True,
        force: bool = True,
    ) -> None:
        """Overrides :meth:`~.os_session.OSSession.remove_remote_dir`."""
        opts = PosixSession.combine_short_options(r=recursive, f=force)
        self.send_command(f"rm{opts} {remote_dir_path}")

    def create_remote_tarball(
        self,
        remote_dir_path: str | PurePath,
        compress_format: TarCompressionFormat = TarCompressionFormat.none,
        exclude: str | list[str] | None = None,
        force: bool = SETTINGS.force,
    ) -> None:
        """Overrides :meth:`~.os_session.OSSession.create_remote_tarball`."""

        def generate_tar_exclude_args(exclude_patterns):
            """Generate args to exclude patterns when creating a tarball.

            Args:
                exclude_patterns: The patterns to exclude from the tarball.

            Returns:
                The generated string args to exclude the specified patterns.
            """
            if exclude_patterns:
                exclude_patterns = ensure_list_of_strings(exclude_patterns)
                return "".join([f" --exclude={pattern}" for pattern in exclude_patterns])
            return ""

        target_tarball_path = f"{remote_dir_path}{compress_format.extension}"
        if force:
            self.remove_remote_file(target_tarball_path)

        self.send_command(
            f"tar caf {target_tarball_path}{generate_tar_exclude_args(exclude)} "
            f"-C {PurePath(remote_dir_path).parent} {PurePath(remote_dir_path).name}",
            60,
        )

    def extract_remote_tarball(
        self,
        remote_tarball_path: str | PurePath,
        expected_dir: str | PurePath | None = None,
        force: bool = SETTINGS.force,
    ) -> None:
        """Overrides :meth:`~.os_session.OSSession.extract_remote_tarball`."""
        if force and expected_dir:
            self.remove_remote_dir(expected_dir)

        self.send_command(
            f"tar xfm {remote_tarball_path} -C {PurePosixPath(remote_tarball_path).parent}",
            60,
        )

        if expected_dir:
            self.send_command(f"ls {expected_dir}", verify=True)

    def get_tarball_top_dir(
        self, remote_tarball_path: str | PurePath
    ) -> str | PurePosixPath | None:
        """Overrides :meth:`~.os_session.OSSession.get_tarball_top_dir`."""
        members = self.send_command(f"tar tf {remote_tarball_path}").stdout.split()
        top_dirs = [PurePosixPath(member).parts[0] for member in members if member]
        if len(set(top_dirs)) == 1:
            return top_dirs[0]
        return None

    def build_dpdk(
        self,
        env_vars: dict,
        meson_args: MesonArgs,
        remote_dpdk_dir: str | PurePath,
        remote_dpdk_build_dir: str | PurePath,
        rebuild: bool = False,
        timeout: float = SETTINGS.compile_timeout,
    ) -> None:
        """Overrides :meth:`~.os_session.OSSession.build_dpdk`."""
        try:
            if rebuild:
                # reconfigure, then build
                self._logger.info("Reconfiguring DPDK build.")
                self.send_command(
                    f"meson configure {meson_args} {remote_dpdk_build_dir}",
                    timeout,
                    verify=True,
                    env=env_vars,
                )
            else:
                # fresh build - remove target dir first, then build from scratch
                self._logger.info("Configuring DPDK build from scratch.")
                self.remove_remote_dir(remote_dpdk_build_dir)
                self.send_command(
                    f"meson setup {meson_args} {remote_dpdk_dir} {remote_dpdk_build_dir}",
                    timeout,
                    verify=True,
                    env=env_vars,
                )

            self._logger.info("Building DPDK.")
            self.send_command(
                f"ninja -C {remote_dpdk_build_dir}", timeout, verify=True, env=env_vars
            )
        except RemoteCommandExecutionError as e:
            raise DPDKBuildError(f"DPDK build failed when doing '{e.command}'.")

    def get_dpdk_version(self, build_dir: str | PurePath) -> str:
        """Overrides :meth:`~.os_session.OSSession.get_dpdk_version`."""
        out = self.send_command(f"cat {self.join_remote_path(build_dir, 'VERSION')}", verify=True)
        return out.stdout

    def kill_cleanup_dpdk_apps(self, dpdk_prefix_list: Iterable[str]) -> None:
        """Overrides :meth:`~.os_session.OSSession.kill_cleanup_dpdk_apps`."""
        self._logger.info("Cleaning up DPDK apps.")
        dpdk_runtime_dirs = self._get_dpdk_runtime_dirs(dpdk_prefix_list)
        if dpdk_runtime_dirs:
            # kill and cleanup only if DPDK is running
            dpdk_pids = self._get_dpdk_pids(dpdk_runtime_dirs)
            for dpdk_pid in dpdk_pids:
                self.send_command(f"kill -9 {dpdk_pid}", 20)
            self._check_dpdk_hugepages(dpdk_runtime_dirs)
            self._remove_dpdk_runtime_dirs(dpdk_runtime_dirs)

    def _get_dpdk_runtime_dirs(self, dpdk_prefix_list: Iterable[str]) -> list[PurePosixPath]:
        """Find runtime directories DPDK apps are currently using.

        Args:
              dpdk_prefix_list: The prefixes DPDK apps were started with.

        Returns:
            The paths of DPDK apps' runtime dirs.
        """
        prefix = PurePosixPath("/var", "run", "dpdk")
        if not dpdk_prefix_list:
            remote_prefixes = self._list_remote_dirs(prefix)
            if not remote_prefixes:
                dpdk_prefix_list = []
            else:
                dpdk_prefix_list = remote_prefixes

        return [PurePosixPath(prefix, dpdk_prefix) for dpdk_prefix in dpdk_prefix_list]

    def _list_remote_dirs(self, remote_path: str | PurePath) -> list[str] | None:
        """Contents of remote_path.

        Args:
            remote_path: List the contents of this path.

        Returns:
            The contents of remote_path. If remote_path doesn't exist, return None.
        """
        out = self.send_command(f"ls -l {remote_path} | awk '/^d/ {{print $NF}}'").stdout
        if "No such file or directory" in out:
            return None
        else:
            return out.splitlines()

    def _get_dpdk_pids(self, dpdk_runtime_dirs: Iterable[str | PurePath]) -> list[int]:
        """Find PIDs of running DPDK apps.

        Look at each "config" file found in dpdk_runtime_dirs and find the PIDs of processes
        that opened those file.

        Args:
            dpdk_runtime_dirs: The paths of DPDK apps' runtime dirs.

        Returns:
            The PIDs of running DPDK apps.
        """
        pids = []
        pid_regex = r"p(\d+)"
        for dpdk_runtime_dir in dpdk_runtime_dirs:
            dpdk_config_file = PurePosixPath(dpdk_runtime_dir, "config")
            if self.remote_path_exists(dpdk_config_file):
                out = self.send_command(f"lsof -Fp {dpdk_config_file}").stdout
                if out and "No such file or directory" not in out:
                    for out_line in out.splitlines():
                        match = re.match(pid_regex, out_line)
                        if match:
                            pids.append(int(match.group(1)))
        return pids

    def _check_dpdk_hugepages(self, dpdk_runtime_dirs: Iterable[str | PurePath]) -> None:
        """Check there aren't any leftover hugepages.

        If any hugepages are found, emit a warning. The hugepages are investigated in the
        "hugepage_info" file of dpdk_runtime_dirs.

        Args:
            dpdk_runtime_dirs: The paths of DPDK apps' runtime dirs.
        """
        for dpdk_runtime_dir in dpdk_runtime_dirs:
            hugepage_info = PurePosixPath(dpdk_runtime_dir, "hugepage_info")
            if self.remote_path_exists(hugepage_info):
                out = self.send_command(f"lsof -Fp {hugepage_info}").stdout
                if out and "No such file or directory" not in out:
                    self._logger.warning("Some DPDK processes did not free hugepages.")
                    self._logger.warning("*******************************************")
                    self._logger.warning(out)
                    self._logger.warning("*******************************************")

    def _remove_dpdk_runtime_dirs(self, dpdk_runtime_dirs: Iterable[str | PurePath]) -> None:
        for dpdk_runtime_dir in dpdk_runtime_dirs:
            self.remove_remote_dir(dpdk_runtime_dir)

    def get_dpdk_file_prefix(self, dpdk_prefix: str) -> str:
        """Overrides :meth:`~.os_session.OSSession.get_dpdk_file_prefix`."""
        return ""

    def get_compiler_version(self, compiler_name: str) -> str:
        """Overrides :meth:`~.os_session.OSSession.get_compiler_version`."""
        match compiler_name:
            case "gcc":
                return self.send_command(
                    f"{compiler_name} --version", SETTINGS.timeout
                ).stdout.split("\n")[0]
            case "clang":
                return self.send_command(
                    f"{compiler_name} --version", SETTINGS.timeout
                ).stdout.split("\n")[0]
            case "msvc":
                return self.send_command("cl", SETTINGS.timeout).stdout
            case "icc":
                return self.send_command(f"{compiler_name} -V", SETTINGS.timeout).stdout
            case _:
                raise ValueError(f"Unknown compiler {compiler_name}")

    def get_node_info(self) -> NodeInfo:
        """Overrides :meth:`~.os_session.OSSession.get_node_info`."""
        os_release_info = self.send_command(
            "awk -F= '$1 ~ /^NAME$|^VERSION$/ {print $2}' /etc/os-release",
            SETTINGS.timeout,
        ).stdout.split("\n")
        kernel_version = self.send_command("uname -r", SETTINGS.timeout).stdout
        return NodeInfo(os_release_info[0].strip(), os_release_info[1].strip(), kernel_version)

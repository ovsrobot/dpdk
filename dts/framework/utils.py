# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation
# Copyright(c) 2022-2023 PANTHEON.tech s.r.o.
# Copyright(c) 2022-2023 University of New Hampshire
# Copyright(c) 2024 Arm Limited

"""Various utility classes and functions.

These are used in multiple modules across the framework. They're here because
they provide some non-specific functionality, greatly simplify imports or just don't
fit elsewhere.

Attributes:
    REGEX_FOR_PCI_ADDRESS: The regex representing a PCI address, e.g. ``0000:00:08.0``.
"""

import atexit
import fnmatch
import json
import os
import subprocess
import tarfile
from enum import Enum
from pathlib import Path
from subprocess import SubprocessError
from typing import Any

from scapy.packet import Packet  # type: ignore[import-untyped]

from .exception import ConfigurationError

REGEX_FOR_PCI_ADDRESS: str = "/[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}.[0-9]{1}/"


def expand_range(range_str: str) -> list[int]:
    """Process `range_str` into a list of integers.

    There are two possible formats of `range_str`:

        * ``n`` - a single integer,
        * ``n-m`` - a range of integers.

    The returned range includes both ``n`` and ``m``. Empty string returns an empty list.

    Args:
        range_str: The range to expand.

    Returns:
        All the numbers from the range.
    """
    expanded_range: list[int] = []
    if range_str:
        range_boundaries = range_str.split("-")
        # will throw an exception when items in range_boundaries can't be converted,
        # serving as type check
        expanded_range.extend(range(int(range_boundaries[0]), int(range_boundaries[-1]) + 1))

    return expanded_range


def get_packet_summaries(packets: list[Packet]) -> str:
    """Format a string summary from `packets`.

    Args:
        packets: The packets to format.

    Returns:
        The summary of `packets`.
    """
    if len(packets) == 1:
        packet_summaries = packets[0].summary()
    else:
        packet_summaries = json.dumps(list(map(lambda pkt: pkt.summary(), packets)), indent=4)
    return f"Packet contents: \n{packet_summaries}"


def get_commit_id(rev_id: str) -> str:
    """Given a Git revision ID, return the corresponding commit ID.

    Args:
        rev_id: The Git revision ID.

    Raises:
        ConfigurationError: The ``git rev-parse`` command failed, suggesting
            an invalid or ambiguous revision ID was supplied.
    """
    result = subprocess.run(
        ["git", "rev-parse", "--verify", rev_id],
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        raise ConfigurationError(
            f"{rev_id} is not a valid git reference.\n"
            f"Command: {result.args}\n"
            f"Stdout: {result.stdout}\n"
            f"Stderr: {result.stderr}"
        )
    return result.stdout.strip()


class StrEnum(Enum):
    """Enum with members stored as strings."""

    @staticmethod
    def _generate_next_value_(name: str, start: int, count: int, last_values: object) -> str:
        return name

    def __str__(self) -> str:
        """The string representation is the name of the member."""
        return self.name


class MesonArgs:
    """Aggregate the arguments needed to build DPDK."""

    _default_library: str

    def __init__(self, default_library: str | None = None, **dpdk_args: str | bool):
        """Initialize the meson arguments.

        Args:
            default_library: The default library type, Meson supports ``shared``, ``static`` and
                ``both``. Defaults to :data:`None`, in which case the argument won't be used.
            dpdk_args: The arguments found in ``meson_options.txt`` in root DPDK directory.
                Do not use ``-D`` with them.

        Example:
            ::

                meson_args = MesonArgs(enable_kmods=True).
        """
        self._default_library = f"--default-library={default_library}" if default_library else ""
        self._dpdk_args = " ".join(
            (
                f"-D{dpdk_arg_name}={dpdk_arg_value}"
                for dpdk_arg_name, dpdk_arg_value in dpdk_args.items()
            )
        )

    def __str__(self) -> str:
        """The actual args."""
        return " ".join(f"{self._default_library} {self._dpdk_args}".split())


class TarCompressionFormat(StrEnum):
    """Compression formats that tar can use.

    Enum names are the shell compression commands
    and Enum values are the associated file extensions.

    The 'none' member represents no compression, only archiving with tar.
    Its value is set to 'tar' to indicate that the file is an uncompressed tar archive.
    """

    none = "tar"
    gzip = "gz"
    compress = "Z"
    bzip2 = "bz2"
    lzip = "lz"
    lzma = "lzma"
    lzop = "lzo"
    xz = "xz"
    zstd = "zst"

    @property
    def extension(self):
        """Return the extension associated with the compression format.

        If the compression format is 'none', the extension will be in the format '.tar'.
        For other compression formats, the extension will be in the format
        '.tar.{compression format}'.
        """
        return f".{self.value}" if self == self.none else f".{self.none.value}.{self.value}"


class DPDKGitTarball:
    """Compressed tarball of DPDK from the repository.

    The class supports the :class:`os.PathLike` protocol,
    which is used to get the Path of the tarball::

        from pathlib import Path
        tarball = DPDKGitTarball("HEAD", "output")
        tarball_path = Path(tarball)
    """

    _git_ref: str
    _tar_compression_format: TarCompressionFormat
    _tarball_dir: Path
    _tarball_name: str
    _tarball_path: Path | None

    def __init__(
        self,
        git_ref: str,
        output_dir: str,
        tar_compression_format: TarCompressionFormat = TarCompressionFormat.xz,
    ):
        """Create the tarball during initialization.

        The DPDK version is specified with `git_ref`. The tarball will be compressed with
        `tar_compression_format`, which must be supported by the DTS execution environment.
        The resulting tarball will be put into `output_dir`.

        Args:
            git_ref: A git commit ID, tag ID or tree ID.
            output_dir: The directory where to put the resulting tarball.
            tar_compression_format: The compression format to use.
        """
        self._git_ref = git_ref
        self._tar_compression_format = tar_compression_format

        self._tarball_dir = Path(output_dir, "tarball")

        self._create_tarball_dir()

        self._tarball_name = f"dpdk-tarball-{self._git_ref}{self._tar_compression_format.extension}"
        self._tarball_path = self._check_tarball_path()
        if not self._tarball_path:
            self._create_tarball()

    def _create_tarball_dir(self) -> None:
        os.makedirs(self._tarball_dir, exist_ok=True)

    def _check_tarball_path(self) -> Path | None:
        if self._tarball_name in os.listdir(self._tarball_dir):
            return Path(self._tarball_dir, self._tarball_name)
        return None

    def _create_tarball(self) -> None:
        self._tarball_path = Path(self._tarball_dir, self._tarball_name)

        atexit.register(self._delete_tarball)

        result = subprocess.run(
            'git -C "$(git rev-parse --show-toplevel)" archive '
            f'{self._git_ref} --prefix="dpdk-tarball-{self._git_ref + os.sep}" | '
            f"{self._tar_compression_format} > {Path(self._tarball_path.absolute())}",
            shell=True,
            text=True,
            capture_output=True,
        )

        if result.returncode != 0:
            raise SubprocessError(
                f"Git archive creation failed with exit code {result.returncode}.\n"
                f"Command: {result.args}\n"
                f"Stdout: {result.stdout}\n"
                f"Stderr: {result.stderr}"
            )

        atexit.unregister(self._delete_tarball)

    def _delete_tarball(self) -> None:
        if self._tarball_path and os.path.exists(self._tarball_path):
            os.remove(self._tarball_path)

    def __fspath__(self) -> str:
        """The os.PathLike protocol implementation."""
        return str(self._tarball_path)


def ensure_list_of_strings(value: Any | list[Any]) -> list[str]:
    """Ensure the input is a list of strings.

    Converting all elements to list of strings format.

    Args:
        value: A single value or a list of values.

    Returns:
        A list of strings.
    """
    return list(map(str, value) if isinstance(value, list) else str(value))


def create_tarball(
    source_path: str | Path,
    compress_format: TarCompressionFormat = TarCompressionFormat.none,
    arcname: str | None = None,
    exclude: Any | list[Any] | None = None,
):
    """Create a tarball archive from a source dir or file.

    The tarball archive will be saved in the same path as `source_path` parent path.

    Args:
        source_path: The path to the source dir or file to be included in the tarball.
        compress_format: The compression format to use. Defaults is no compression.
        arcname: The name under which `source_path` will be archived.
        exclude: Files or dirs to exclude before creating the tarball.
    """

    def create_filter_function(exclude_patterns: str | list[str] | None):
        """Create a filter function based on the provided exclude patterns.

        Args:
            exclude_patterns: The patterns to exclude from the tarball.

        Returns:
            The filter function that excludes files based on the patterns.
        """
        if exclude_patterns:
            exclude_patterns = ensure_list_of_strings(exclude_patterns)

            def filter_func(tarinfo: tarfile.TarInfo) -> tarfile.TarInfo | None:
                file_name = os.path.basename(tarinfo.name)
                if any(fnmatch.fnmatch(file_name, pattern) for pattern in exclude_patterns):
                    return None
                return tarinfo

            return filter_func
        return None

    with tarfile.open(
        f"{source_path}{compress_format.extension}", f"w:{compress_format.value}"
    ) as tar:
        tar.add(source_path, arcname=arcname, filter=create_filter_function(exclude))


def extract_tarball(tar_path: str | Path):
    """Extract the contents of a tarball.

    The tarball will be extracted in the same path as `tar_path` parent path.

    Args:
        tar_path: The path to the tarball file to extract.
    """
    with tarfile.open(tar_path, "r") as tar:
        tar.extractall(path=Path(tar_path).parent)

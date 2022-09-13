#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2016  Neil Horman <nhorman@tuxdriver.com>
# Copyright(c) 2022  Robin Jarry
# pylint: disable=invalid-name

r"""
Utility to dump PMD_INFO_STRING support from DPDK binaries.

This script prints JSON output to be interpreted by other tools. Here are some
examples with jq:

Get the complete info for a given driver:

  %(prog)s dpdk-testpmd | \
  jq '.[] | select(.name == "cnxk_nix_inl")'

Get only the required kernel modules for a given driver:

  %(prog)s dpdk-testpmd | \
  jq '.[] | select(.name == "net_i40e").kmod'

Get only the required kernel modules for a given device:

  %(prog)s dpdk-testpmd | \
  jq '.[] | select(.devices[] | .vendor_id == "15b3" and .device_id == "1013").kmod'
"""

import argparse
import json
import os
import re
import string
import sys
from pathlib import Path
from typing import Iterable, Iterator, List, Union

import elftools
from elftools.elf.elffile import ELFError, ELFFile


# ----------------------------------------------------------------------------
def main() -> int:  # pylint: disable=missing-docstring
    try:
        args = parse_args()
        info = parse_pmdinfo(args.elf_files, args.search_plugins)
        json.dump(info, sys.stdout, indent=2)
        sys.stdout.write("\n")
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        return 1
    except Exception as e:  # pylint: disable=broad-except
        print(f"error: {e}", file=sys.stderr)
        return 1

    return 0


# ----------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    """
    Parse command line arguments.
    """
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-p",
        "--search-plugins",
        action="store_true",
        help="""
        In addition of ELF_FILEs and their linked dynamic libraries, also scan
        the DPDK plugins path.
        """,
    )
    parser.add_argument(
        "elf_files",
        metavar="ELF_FILE",
        nargs="+",
        type=existing_file,
        help="""
        DPDK application binary or dynamic library.
        """,
    )
    return parser.parse_args()


# ----------------------------------------------------------------------------
def parse_pmdinfo(paths: Iterable[Path], search_plugins: bool) -> List[dict]:
    """
    Extract DPDK PMD info JSON strings from an ELF file.

    :returns:
        A list of DPDK drivers info dictionaries.
    """
    binaries = set(paths)
    for p in paths:
        binaries.update(get_needed_libs(p))
    if search_plugins:
        # cast to list to avoid errors with update while iterating
        binaries.update(list(get_plugin_libs(binaries)))

    drivers = []

    for b in binaries:
        try:
            for s in get_elf_strings(b, ".rodata", "PMD_INFO_STRING="):
                try:
                    info = json.loads(s)
                    # convert numerical ids to hex strings
                    info["devices"] = []
                    for vendor, device, subdev, subsys in info.pop("pci_ids"):
                        info["devices"].append(
                            {
                                "vendor_id": f"{vendor:04x}",
                                "device_id": f"{device:04x}",
                                "subsystem_device_id": f"{subdev:04x}",
                                "subsystem_system_id": f"{subsys:04x}",
                            }
                        )
                    drivers.append(info)
                except ValueError as e:
                    print(f"warning: {b}: {e}", file=sys.stderr)
        except FileNotFoundError as e:
            print(f"warning: {b}: {e}", file=sys.stderr)
        except ELFError as e:
            print(f"warning: {b}: elf error: {e}", file=sys.stderr)

    return drivers


# ----------------------------------------------------------------------------
def get_plugin_libs(binaries: Iterable[Path]) -> Iterator[Path]:
    """
    Look into the provided binaries for DPDK_PLUGIN_PATH and scan the path
    for files.
    """
    for b in binaries:
        for p in get_elf_strings(b, ".rodata", "DPDK_PLUGIN_PATH="):
            plugin_path = p.strip()
            for root, _, files in os.walk(plugin_path):
                for f in files:
                    yield Path(root) / f
            # no need to search in other binaries.
            return


# ----------------------------------------------------------------------------
def existing_file(value: str) -> Path:
    """
    Argparse type= callback to ensure an argument points to a valid file path.
    """
    path = Path(value)
    if not path.is_file():
        raise argparse.ArgumentTypeError(f"{value}: No such file")
    return path


# ----------------------------------------------------------------------------
def search_ld_library_path(name: str) -> Path:
    """
    Search a file into LD_LIBRARY_PATH and the standard folders where libraries
    are usually located.

    :raises FileNotFoundError:
    """
    folders = []
    if "LD_LIBRARY_PATH" in os.environ:
        folders += os.environ["LD_LIBRARY_PATH"].split(":")
    folders += ["/usr/lib64", "/lib64", "/usr/lib", "/lib"]
    for d in folders:
        filepath = Path(d) / name
        if filepath.is_file():
            return filepath
    raise FileNotFoundError(name)


# ----------------------------------------------------------------------------
PRINTABLE_BYTES = frozenset(string.printable.encode("ascii"))


def find_strings(buf: bytes, prefix: str) -> Iterator[str]:
    """
    Extract strings of printable ASCII characters from a bytes buffer.
    """
    view = memoryview(buf)
    start = None

    for i, b in enumerate(view):
        if start is None and b in PRINTABLE_BYTES:
            # mark begining of string
            start = i
            continue

        if start is not None:
            if b in PRINTABLE_BYTES:
                # string not finished
                continue
            if b == 0:
                # end of string
                s = view[start:i].tobytes().decode("ascii")
                if s.startswith(prefix):
                    yield s[len(prefix) :]
            # There can be byte sequences where a non-printable character
            # follows a printable one. Ignore that.
            start = None


# ----------------------------------------------------------------------------
def elftools_version():
    """
    Extract pyelftools version as a tuple of integers for easy comparison.
    """
    version = getattr(elftools, "__version__", "")
    match = re.match(r"^(\d+)\.(\d+).*$", str(version))
    if not match:
        # cannot determine version, hope for the best
        return (0, 24)
    return (int(match[1]), int(match[2]))


ELFTOOLS_VERSION = elftools_version()


def from_elftools(s: Union[bytes, str]) -> str:
    """
    Earlier versions of pyelftools (< 0.24) return bytes encoded with "latin-1"
    instead of python strings.
    """
    if isinstance(s, bytes):
        return s.decode("latin-1")
    return s


def to_elftools(s: str) -> Union[bytes, str]:
    """
    Earlier versions of pyelftools (< 0.24) assume that ELF section and tags
    are bytes encoded with "latin-1" instead of python strings.
    """
    if ELFTOOLS_VERSION < (0, 24):
        return s.encode("latin-1")
    return s


# ----------------------------------------------------------------------------
def get_elf_strings(path: Path, section: str, prefix: str) -> Iterator[str]:
    """
    Extract strings from a named ELF section in a file.
    """
    with path.open("rb") as f:
        elf = ELFFile(f)
        sec = elf.get_section_by_name(to_elftools(section))
        if not sec:
            return
        yield from find_strings(sec.data(), prefix)


# ----------------------------------------------------------------------------
def get_needed_libs(path: Path) -> Iterator[Path]:
    """
    Extract the dynamic library dependencies from an ELF file.
    """
    with path.open("rb") as f:
        elf = ELFFile(f)
        dyn = elf.get_section_by_name(to_elftools(".dynamic"))
        if not dyn:
            return
        for tag in dyn.iter_tags(to_elftools("DT_NEEDED")):
            needed = from_elftools(tag.needed)
            if not needed.startswith("librte_"):
                continue
            try:
                yield search_ld_library_path(needed)
            except FileNotFoundError:
                print(f"warning: cannot find {needed}", file=sys.stderr)


# ----------------------------------------------------------------------------
if __name__ == "__main__":
    sys.exit(main())

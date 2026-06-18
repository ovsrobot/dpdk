#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause

"""Check symbol consistency between exports and flags in DPDK."""

import argparse
import sys
import re
import struct
import io
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, Set, List, Optional, Iterator
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection


@dataclass
class ValidationError:
    """Represents a symbol consistency validation error."""
    symbol: str
    message: str


@dataclass
class ArchiveMember:
    """Represents a member file within an archive."""
    name: str
    data: bytes
    size: int


class ArchiveParser:
    """Pure Python parser for Unix archive (.a) files."""

    MAGIC = b'!<arch>\n'
    MEMBER_HEADER_SIZE = 60

    def __init__(self, archive_path: Path):
        self.archive_path = archive_path

    def parse_members(self) -> Iterator[ArchiveMember]:
        """Parse archive file and yield member files."""
        try:
            with open(self.archive_path, 'rb') as f:
                magic = f.read(8)
                if magic != self.MAGIC:
                    raise ValueError(f"Invalid archive magic: {magic}")

                while True:
                    member = self._parse_member(f)
                    if member is None:
                        break
                    yield member

        except IOError as e:
            print(f"Error reading archive {self.archive_path}: {e}", file=sys.stderr)

    def _parse_member(self, f) -> Optional[ArchiveMember]:
        """Parse a single member from the archive."""
        header_data = f.read(self.MEMBER_HEADER_SIZE)
        if len(header_data) < self.MEMBER_HEADER_SIZE:
            return None

        # Parse header fields
        # Format: name(16) + date(12) + uid(6) + gid(6) + mode(8) + size(10) + end(2)
        header = struct.unpack('16s12s6s6s8s10s2s', header_data)

        name = header[0].decode('ascii', errors='ignore').rstrip('\x00 ')
        size_str = header[5].decode('ascii', errors='ignore').rstrip('\x00 ')

        try:
            size = int(size_str)
        except ValueError:
            return None

        if name.startswith('/') or name == '':
            f.seek(size, 1)
            if size % 2:
                f.read(1)
            return self._parse_member(f)

        data = f.read(size)
        if len(data) != size:
            return None

        if size % 2:
            f.read(1)

        return ArchiveMember(name=name, data=data, size=size)


class VersionMapParser:
    """Parse GNU linker version map files to extract symbol sections."""

    def __init__(self, map_file: Path):
        self.map_file = map_file
        self.symbols_by_section: Dict[str, Set[str]] = {}
        self._parse_map_file()

    def _parse_map_file(self):
        """Parse the version map file and extract symbols by section."""
        try:
            with open(self.map_file, 'r', encoding='utf-8') as f:
                content = f.read()
        except IOError as e:
            print(f"Error reading map file {self.map_file}: {e}", file=sys.stderr)
            sys.exit(1)

        current_section = None
        in_global_block = False

        for line in content.splitlines():
            line = line.strip()

            section_match = re.match(r'^(\w+)\s*\{', line)
            if section_match:
                current_section = section_match.group(1)
                self.symbols_by_section.setdefault(current_section, set())
                in_global_block = False
                continue

            if line == "global:":
                in_global_block = True
                continue

            if line == "};":
                current_section = None
                in_global_block = False
                continue

            if line.startswith("local:"):
                in_global_block = False
                continue

            if current_section and in_global_block and line and not line.startswith("local:"):
                symbol_line = line.split(';')[0].strip()
                comment_split = symbol_line.split('#')
                symbol = comment_split[0].strip()

                if symbol and not symbol.startswith('}'):
                    self.symbols_by_section[current_section].add(symbol)

    def get_symbols_by_section(self, section: str) -> Set[str]:
        """Get all symbols in a specific section."""
        return self.symbols_by_section.get(section, set())

    def symbol_in_section(self, symbol: str, section: str) -> bool:
        """Check if a symbol exists in a specific section."""
        return symbol in self.get_symbols_by_section(section)


class ELFSymbolAnalyzer:
    """Analyze archive files to extract symbol information from contained objects."""

    def __init__(self, archive_file: Path):
        self.archive_file = archive_file
        self.text_symbols: Set[str] = set()
        self.experimental_symbols: Set[str] = set()
        self.internal_symbols: Set[str] = set()

        self._analyze_archive_file()

    def _analyze_archive_file(self):
        """Extract and analyze all object files from archive using native parser."""
        try:
            archive_parser = ArchiveParser(self.archive_file)

            for member in archive_parser.parse_members():
                if member.name.endswith('.o'):
                    self._analyze_archived_object(member)

        except Exception as e:
            print(f"Error processing archive {self.archive_file}: {e}", file=sys.stderr)
            sys.exit(1)

    def _analyze_archived_object(self, member: ArchiveMember):
        """Analyze a single object file member from archive."""
        try:
            elf_data = io.BytesIO(member.data)
            elffile = ELFFile(elf_data)
            self._extract_symbols(elffile)

        except Exception as e:
            print(f"Warning: Error analyzing {member.name}: {e}", file=sys.stderr)


    def _extract_symbols(self, elffile: ELFFile):
        """Extract symbol information from the ELF file."""
        section_names = {}
        for i, section in enumerate(elffile.iter_sections()):
            section_names[i] = section.name

        for section in elffile.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue

            for symbol in section.iter_symbols():
                symbol_name = symbol.name

                if not symbol_name or symbol['st_shndx'] == 'SHN_UNDEF':
                    continue

                section_index = symbol['st_shndx']
                if isinstance(section_index, int) and section_index in section_names:
                    section_name = section_names[section_index]

                    if section_name.startswith('.text'):
                        self.text_symbols.add(symbol_name)

                        if section_name == '.text.experimental':
                            self.experimental_symbols.add(symbol_name)
                        elif section_name == '.text.internal':
                            self.internal_symbols.add(symbol_name)

    def symbol_in_text(self, symbol: str) -> bool:
        """Check if symbol exists in any .text section."""
        return symbol in self.text_symbols

    def symbol_in_experimental_section(self, symbol: str) -> bool:
        """Check if symbol exists in .text.experimental section."""
        return symbol in self.experimental_symbols

    def symbol_in_internal_section(self, symbol: str) -> bool:
        """Check if symbol exists in .text.internal section."""
        return symbol in self.internal_symbols


class SymbolConsistencyChecker:
    """Main checker that orchestrates all symbol consistency validations."""

    def __init__(self, map_file: Path, archive_file: Path):
        self.map_parser = VersionMapParser(map_file)
        self.elf_analyzer = ELFSymbolAnalyzer(archive_file)
        self.errors: List[ValidationError] = []

    def check_experimental_consistency(self):
        """Check consistency between experimental exports and flags."""

        # Check 1: Symbols exported as experimental but not flagged with __rte_experimental
        for symbol in self.map_parser.get_symbols_by_section("EXPERIMENTAL"):
            if (self.elf_analyzer.symbol_in_text(symbol) and
                not self.elf_analyzer.symbol_in_experimental_section(symbol)):
                self.errors.append(ValidationError(
                    symbol=symbol,
                    message=f"{symbol} is not flagged as experimental but is exported as an experimental symbol\n"
                           f"Please add __rte_experimental to the definition of {symbol}"
                ))

        # Check 2: Symbols flagged as experimental but not exported
        for symbol in self.elf_analyzer.experimental_symbols:
            if not self.map_parser.symbol_in_section(symbol, "EXPERIMENTAL"):
                self.errors.append(ValidationError(
                    symbol=symbol,
                    message=f"{symbol} is flagged as experimental but is not exported as an experimental symbol\n"
                           f"Please add RTE_EXPORT_EXPERIMENTAL_SYMBOL to the definition of {symbol}"
                ))

    def check_internal_consistency(self):
        """Check consistency between internal exports and flags."""

        # Check 3: Symbols exported as internal but not flagged with __rte_internal
        for symbol in self.map_parser.get_symbols_by_section("INTERNAL"):
            if (self.elf_analyzer.symbol_in_text(symbol) and
                not self.elf_analyzer.symbol_in_internal_section(symbol)):
                self.errors.append(ValidationError(
                    symbol=symbol,
                    message=f"{symbol} is not flagged as internal but is exported as an internal symbol\n"
                           f"Please add __rte_internal to the definition of {symbol}"
                ))

        # Check 4: Symbols flagged as internal but not exported
        for symbol in self.elf_analyzer.internal_symbols:
            if not self.map_parser.symbol_in_section(symbol, "INTERNAL"):
                self.errors.append(ValidationError(
                    symbol=symbol,
                    message=f"{symbol} is flagged as internal but is not exported as an internal symbol\n"
                           f"Please add RTE_EXPORT_INTERNAL_SYMBOL to the definition of {symbol}"
                ))

    def run_all_checks(self) -> int:
        """Run all consistency checks and return exit code."""
        self.check_experimental_consistency()
        self.check_internal_consistency()

        for error in self.errors:
            print(error.message, file=sys.stderr)

        return 1 if self.errors else 0


def main() -> int:
    """Main entry point for the symbol consistency checker."""
    parser = argparse.ArgumentParser(
        description="Check symbol consistency between exports and flags in DPDK libraries.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "map_file",
        type=Path,
        help="Version map file (e.g., lib_exports.map)"
    )
    parser.add_argument(
        "archive_file",
        type=Path,
        help="Archive file to analyze (static library .a file)"
    )

    args = parser.parse_args()

    if not args.map_file.exists():
        print(f"Error: Map file {args.map_file} does not exist", file=sys.stderr)
        return 1

    if not args.archive_file.exists():
        print(f"Error: Archive file {args.archive_file} does not exist", file=sys.stderr)
        return 1

    checker = SymbolConsistencyChecker(args.map_file, args.archive_file)
    return checker.run_all_checks()


if __name__ == "__main__":
    sys.exit(main())

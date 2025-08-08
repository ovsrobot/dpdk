#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2025 Intel Corporation

"""
A tool for manipulating the .mailmap file in DPDK repository.

This script supports three operations:
- add: adds a new entry to the mailmap file in the correct position
- check: validates mailmap entries are sorted and correctly formatted
- sort: sorts the mailmap entries alphabetically by name
"""

import sys
import os
import re
import argparse
import unicodedata
from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class MailmapEntry:
    """Represents a single mailmap entry."""

    name: str
    name_for_sorting: str
    email1: str
    email2: Optional[str]
    line_number: int

    def __str__(self) -> str:
        """Format the entry back to mailmap string format."""
        return f"{self.name} <{self.email1}>" + (f" <{self.email2}>" if self.email2 else "")

    @staticmethod
    def _get_name_for_sorting(name):
        """Normalize a name for sorting purposes."""
        # Remove accents/diacritics. Separate accented chars into two - so accent is separate,
        # then remove the accent.
        normalized = unicodedata.normalize("NFD", name)
        normalized = "".join(c for c in normalized if unicodedata.category(c) != "Mn")

        return normalized.lower()

    @classmethod
    def parse(cls, line: str, line_number: int) -> Optional["MailmapEntry"]:
        """
        Parse a mailmap line and create a MailmapEntry instance.

        Valid formats:
        - Name <email>
        - Name <primary_email> <secondary_email>
        """
        line = line.strip()
        if not line or line.startswith("#"):
            return None

        # Pattern to match mailmap entries
        # Group 1: Name, Group 2: first email, Group 3: optional second email
        pattern = r"^([^<]+?)\s*<([^>]+)>(?:\s*<([^>]+)>)?$"
        match = re.match(pattern, line)
        if not match:
            return None

        name = match.group(1).strip()
        primary_email = match.group(2).strip()
        secondary_email = match.group(3).strip() if match.group(3) else None

        return cls(
            name=name,
            name_for_sorting=cls._get_name_for_sorting(name),
            email1=primary_email,
            email2=secondary_email,
            line_number=line_number,
        )


def read_and_parse_mailmap(mailmap_path: Path) -> List[MailmapEntry]:
    """Read and parse a mailmap file, returning entries."""
    try:
        with open(mailmap_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except IOError as e:
        print(f"Error reading {mailmap_path}: {e}", file=sys.stderr)
        sys.exit(1)

    entries = []
    line_num = 0

    for line in lines:
        line_num += 1
        stripped_line = line.strip()

        # Skip empty lines and comments
        if not stripped_line or stripped_line.startswith("#"):
            continue

        entry = MailmapEntry.parse(stripped_line, line_num)
        if entry is None:
            print(f"Line {line_num}: Invalid format - {stripped_line}", file=sys.stderr)
            continue

        # Check for more than two email addresses
        if stripped_line.count("<") > 2:
            print(f"Line {line_num}: Too many email addresses - {stripped_line}", file=sys.stderr)

        entries.append(entry)
    return entries


def write_entries_to_file(mailmap_path: Path, entries: List[MailmapEntry]):
    """Write entries to mailmap file."""
    try:
        with open(mailmap_path, "w", encoding="utf-8") as f:
            for entry in entries:
                f.write(str(entry) + "\n")
    except IOError as e:
        print(f"Error writing {mailmap_path}: {e}", file=sys.stderr)
        sys.exit(1)


def check_mailmap(mailmap_path, _):
    """Check that mailmap entries are correctly sorted and formatted."""
    entries = read_and_parse_mailmap(mailmap_path)

    errors = 0
    for i in range(1, len(entries)):
        if entries[i].name_for_sorting < entries[i - 1].name_for_sorting:
            print(
                f"Line {entries[i].line_number}: Entry '{entries[i].name}' is incorrectly sorted",
                file=sys.stderr,
            )
            errors += 1

    if errors:
        sys.exit(1)


def sort_mailmap(mailmap_path, _):
    """Sort the mailmap entries alphabetically by name."""
    entries = read_and_parse_mailmap(mailmap_path)

    entries.sort(key=lambda x: x.name_for_sorting)
    write_entries_to_file(mailmap_path, entries)


def add_entry(mailmap_path, args):
    """Add a new entry to the mailmap file in the correct alphabetical position."""
    if not args.entry:
        print("Error: 'add' operation requires an entry argument", file=sys.stderr)
        sys.exit(1)

    new_entry = MailmapEntry.parse(args.entry, 0)
    if new_entry is None:
        print(f"Error: Invalid entry format: {args.entry}", file=sys.stderr)
        sys.exit(1)

    entries = read_and_parse_mailmap(mailmap_path)

    # Check if entry already exists, checking email2 only if it's specified
    if (
        not new_entry.email2
        and any(e.name == new_entry.name and e.email1 == new_entry.email1 for e in entries)
    ) or any(
        e.name == new_entry.name and e.email1 == new_entry.email1 and e.email2 == new_entry.email2
        for e in entries
    ):
        print(
            f"Warning: Duplicate entry for '{new_entry.name} <{new_entry.email1}>' already exists",
            file=sys.stderr,
        )
        sys.exit(1)

    entries.append(new_entry)
    entries.sort(key=lambda x: x.name_for_sorting)
    write_entries_to_file(mailmap_path, entries)


def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("operation", choices=["check", "add", "sort"], help="Operation to perform")
    parser.add_argument("--mailmap", help="Path to .mailmap file (default: search up tree)")
    parser.add_argument("entry", nargs="?", help='Entry to add. Format: "Name <email@domain.com>"')

    args = parser.parse_args()

    if args.mailmap:
        mailmap_path = Path(args.mailmap)
    else:
        # Find mailmap file
        mailmap_path = Path(".").resolve()
        while not (mailmap_path / ".mailmap").exists():
            if mailmap_path == mailmap_path.parent:
                print("Error: No .mailmap file found", file=sys.stderr)
                sys.exit(1)
            mailmap_path = mailmap_path.parent
        mailmap_path = mailmap_path / ".mailmap"

    # Handle operations
    operations = {"add": add_entry, "check": check_mailmap, "sort": sort_mailmap}
    operations[args.operation](mailmap_path, args)


if __name__ == "__main__":
    main()

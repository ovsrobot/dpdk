#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation
# Copyright(c) 2025 - Python rewrite
#
# get_maintainer.py - Find maintainers and mailing lists for patches/files
#
# Based on the Linux kernel's get_maintainer.pl by Joe Perches
# and DPDK's get-maintainer.sh wrapper script.
#
# Usage: get_maintainer.py [OPTIONS] <patch>
#        get_maintainer.py [OPTIONS] -f <file>

import argparse
import os
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

VERSION = "1.0"

# Default configuration
DEFAULT_CONFIG = {
    "email": True,
    "email_usename": True,
    "email_maintainer": True,
    "email_reviewer": True,
    "email_fixes": True,
    "email_list": True,
    "email_moderated_list": True,
    "email_subscriber_list": False,
    "email_git": False,
    "email_git_all_signature_types": False,
    "email_git_blame": False,
    "email_git_blame_signatures": True,
    "email_git_fallback": True,
    "email_git_min_signatures": 1,
    "email_git_max_maintainers": 5,
    "email_git_min_percent": 5,
    "email_git_since": "1-year-ago",
    "email_remove_duplicates": True,
    "email_use_mailmap": True,
    "output_multiline": True,
    "output_separator": ", ",
    "output_roles": False,
    "output_rolestats": True,
    "output_section_maxlen": 50,
    "scm": False,
    "web": False,
    "bug": False,
    "subsystem": False,
    "status": False,
    "keywords": True,
    "keywords_in_file": False,
    "sections": False,
    "email_file_emails": False,
    "from_filename": False,
    "pattern_depth": 0,
}

# Signature tags for git commit analysis
SIGNATURE_TAGS = [
    "Signed-off-by:",
    "Reviewed-by:",
    "Acked-by:",
]


@dataclass
class MaintainerEntry:
    """Represents a maintainer/list entry with role information."""
    email: str
    role: str = ""

    def __hash__(self):
        return hash(self.email.lower())

    def __eq__(self, other):
        if isinstance(other, MaintainerEntry):
            return self.email.lower() == other.email.lower()
        return False


@dataclass
class Section:
    """Represents a MAINTAINERS file section."""
    name: str
    maintainers: list = field(default_factory=list)
    reviewers: list = field(default_factory=list)
    mailing_lists: list = field(default_factory=list)
    status: str = ""
    files: list = field(default_factory=list)
    excludes: list = field(default_factory=list)
    scm: list = field(default_factory=list)
    web: list = field(default_factory=list)
    bug: list = field(default_factory=list)
    keywords: list = field(default_factory=list)
    regex_patterns: list = field(default_factory=list)


class GetMaintainer:
    """Main class for finding maintainers."""

    def __init__(self, config: dict):
        self.config = config
        self.sections: list[Section] = []
        self.mailmap: dict = {"names": {}, "addresses": {}}
        self.ignore_emails: list[str] = []
        self.vcs_type: Optional[str] = None
        self.root_path = self._find_root_path()

        # Results
        self.email_to: list[MaintainerEntry] = []
        self.list_to: list[MaintainerEntry] = []
        self.scm_list: list[str] = []
        self.web_list: list[str] = []
        self.bug_list: list[str] = []
        self.subsystem_list: list[str] = []
        self.status_list: list[str] = []

        # Deduplication tracking
        self.email_hash_name: dict = {}
        self.email_hash_address: dict = {}
        self.deduplicate_name_hash: dict = {}
        self.deduplicate_address_hash: dict = {}

    def _find_root_path(self) -> Path:
        """Find the root path of the project."""
        cwd = Path.cwd()

        # Check for MAINTAINERS file in current directory or parents
        for parent in [cwd] + list(cwd.parents):
            if (parent / "MAINTAINERS").exists():
                return parent
            # Also check for common project indicators
            if (parent / ".git").exists() or (parent / ".hg").exists():
                if (parent / "MAINTAINERS").exists():
                    return parent

        return cwd

    def _detect_vcs(self) -> Optional[str]:
        """Detect if git is available."""
        if self.vcs_type is not None:
            return self.vcs_type

        # Check for git
        if (self.root_path / ".git").exists():
            try:
                subprocess.run(
                    ["git", "--version"],
                    capture_output=True,
                    check=True
                )
                self.vcs_type = "git"
                return "git"
            except (subprocess.CalledProcessError, FileNotFoundError):
                pass

        self.vcs_type = None
        return None

    def load_maintainers_file(self, path: Optional[Path] = None) -> None:
        """Load and parse the MAINTAINERS file."""
        if path is None:
            path = self.root_path / "MAINTAINERS"

        if not path.exists():
            print(f"Error: MAINTAINERS file not found: {path}", file=sys.stderr)
            sys.exit(1)

        current_section: Optional[Section] = None

        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n\r")

                # Skip empty lines and comments at the start
                if not line or line.startswith("#"):
                    continue

                # Check for section header (line not starting with a type letter)
                match = re.match(r"^([A-Z]):\s*(.*)$", line)
                if match:
                    type_char = match.group(1)
                    value = match.group(2)

                    if current_section is None:
                        # Create a default section for entries before any header
                        current_section = Section(name="THE REST")
                        self.sections.append(current_section)

                    self._process_section_entry(current_section, type_char, value)
                elif line and not line[0].isspace():
                    # New section header
                    current_section = Section(name=line.strip())
                    self.sections.append(current_section)

    def _process_section_entry(self, section: Section, type_char: str, value: str) -> None:
        """Process a single entry in a MAINTAINERS section."""
        if type_char == "M":
            section.maintainers.append(value)
        elif type_char == "R":
            section.reviewers.append(value)
        elif type_char == "L":
            section.mailing_lists.append(value)
        elif type_char == "S":
            section.status = value
        elif type_char == "F":
            # Convert glob pattern to regex
            pattern = self._glob_to_regex(value)
            section.files.append((value, pattern))
        elif type_char == "X":
            pattern = self._glob_to_regex(value)
            section.excludes.append((value, pattern))
        elif type_char == "N":
            # Regex pattern for filename matching
            section.regex_patterns.append(value)
        elif type_char == "K":
            section.keywords.append(value)
        elif type_char == "T":
            section.scm.append(value)
        elif type_char == "W":
            section.web.append(value)
        elif type_char == "B":
            section.bug.append(value)

    def _glob_to_regex(self, pattern: str) -> str:
        """Convert a glob pattern to a regex pattern."""
        # Escape special regex characters except * and ?
        result = re.escape(pattern)
        # Convert glob wildcards to regex
        result = result.replace(r"\*", ".*")
        result = result.replace(r"\?", ".")
        # Handle directory patterns
        if pattern.endswith("/") or os.path.isdir(pattern):
            if not result.endswith("/"):
                result += "/"
            result += ".*"
        return f"^{result}"

    def load_mailmap(self) -> None:
        """Load the .mailmap file for email address mapping."""
        mailmap_path = self.root_path / ".mailmap"
        if not mailmap_path.exists():
            return

        try:
            with open(mailmap_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = re.sub(r"#.*$", "", line).strip()
                    if not line:
                        continue

                    # Parse different mailmap formats
                    # name1 <mail1>
                    match = re.match(r"^([^<]+)<([^>]+)>$", line)
                    if match:
                        name = match.group(1).strip()
                        address = match.group(2).strip()
                        self.mailmap["names"][address.lower()] = name
                        continue

                    # <mail1> <mail2>
                    match = re.match(r"^<([^>]+)>\s*<([^>]+)>$", line)
                    if match:
                        real_addr = match.group(1).strip()
                        wrong_addr = match.group(2).strip()
                        self.mailmap["addresses"][wrong_addr.lower()] = real_addr
                        continue

                    # name1 <mail1> <mail2>
                    match = re.match(r"^(.+)<([^>]+)>\s*<([^>]+)>$", line)
                    if match:
                        name = match.group(1).strip()
                        real_addr = match.group(2).strip()
                        wrong_addr = match.group(3).strip()
                        self.mailmap["names"][wrong_addr.lower()] = name
                        self.mailmap["addresses"][wrong_addr.lower()] = real_addr
                        continue

                    # name1 <mail1> name2 <mail2>
                    match = re.match(r"^(.+)<([^>]+)>\s*(.+)\s*<([^>]+)>$", line)
                    if match:
                        real_name = match.group(1).strip()
                        real_addr = match.group(2).strip()
                        wrong_addr = match.group(4).strip()
                        wrong_email = f"{match.group(3).strip()} <{wrong_addr}>"
                        self.mailmap["names"][wrong_email.lower()] = real_name
                        self.mailmap["addresses"][wrong_email.lower()] = real_addr

        except IOError as e:
            print(f"Warning: Could not read .mailmap: {e}", file=sys.stderr)

    def load_ignore_file(self) -> None:
        """Load the .get_maintainer.ignore file."""
        for search_path in [".", os.environ.get("HOME", ""), ".scripts"]:
            ignore_path = Path(search_path) / ".get_maintainer.ignore"
            if ignore_path.exists():
                try:
                    with open(ignore_path, "r", encoding="utf-8") as f:
                        for line in f:
                            line = re.sub(r"#.*$", "", line).strip()
                            if line and self._is_valid_email(line):
                                self.ignore_emails.append(line.lower())
                except IOError:
                    pass
                break

    def load_config_file(self) -> dict:
        """Load configuration from .get_maintainer.conf file."""
        config_args = []
        for search_path in [".", os.environ.get("HOME", ""), ".scripts"]:
            conf_path = Path(search_path) / ".get_maintainer.conf"
            if conf_path.exists():
                try:
                    with open(conf_path, "r", encoding="utf-8") as f:
                        for line in f:
                            line = re.sub(r"#.*$", "", line).strip()
                            if line:
                                config_args.extend(line.split())
                except IOError:
                    pass
                break
        return config_args

    def _is_valid_email(self, email: str) -> bool:
        """Basic email validation."""
        return bool(re.match(r"^[^@]+@[^@]+\.[^@]+$", email))

    def parse_email(self, formatted_email: str) -> tuple[str, str]:
        """Parse an email address into name and address components."""
        name = ""
        address = ""

        # Name <email@domain.com>
        match = re.match(r"^([^<]+)<(.+@.*)>.*$", formatted_email)
        if match:
            name = match.group(1).strip().strip('"')
            address = match.group(2).strip()
            return name, address

        # <email@domain.com>
        match = re.match(r"^\s*<(.+@\S*)>.*$", formatted_email)
        if match:
            address = match.group(1).strip()
            return name, address

        # email@domain.com
        match = re.match(r"^(.+@\S*).*$", formatted_email)
        if match:
            address = match.group(1).strip()

        return name, address

    def format_email(self, name: str, address: str, use_name: bool = True) -> str:
        """Format name and address into a proper email string."""
        name = name.strip().strip('"')
        address = address.strip()

        # Escape special characters in name
        if name and re.search(r'[^\w\s\-]', name):
            name = f'"{name}"'

        if use_name and name:
            return f"{name} <{address}>"
        return address

    def mailmap_email(self, email: str) -> str:
        """Apply mailmap transformations to an email address."""
        name, address = self.parse_email(email)
        formatted = self.format_email(name, address, True)

        real_name = name
        real_address = address

        # Check by full email first
        if formatted.lower() in self.mailmap["names"]:
            real_name = self.mailmap["names"][formatted.lower()]
        elif address.lower() in self.mailmap["names"]:
            real_name = self.mailmap["names"][address.lower()]

        if formatted.lower() in self.mailmap["addresses"]:
            real_address = self.mailmap["addresses"][formatted.lower()]
        elif address.lower() in self.mailmap["addresses"]:
            real_address = self.mailmap["addresses"][address.lower()]

        return self.format_email(real_name, real_address, True)

    def deduplicate_email(self, email: str) -> str:
        """Deduplicate and normalize an email address."""
        name, address = self.parse_email(email)
        email = self.format_email(name, address, True)
        email = self.mailmap_email(email)

        if not self.config["email_remove_duplicates"]:
            return email

        name, address = self.parse_email(email)

        if name and name.lower() in self.deduplicate_name_hash:
            stored = self.deduplicate_name_hash[name.lower()]
            name, address = stored
        elif address.lower() in self.deduplicate_address_hash:
            stored = self.deduplicate_address_hash[address.lower()]
            name, address = stored
        else:
            self.deduplicate_name_hash[name.lower()] = (name, address)
            self.deduplicate_address_hash[address.lower()] = (name, address)

        return self.format_email(name, address, True)

    def file_matches_pattern(self, filepath: str, pattern: str, regex: str) -> bool:
        """Check if a file matches a pattern."""
        try:
            return bool(re.match(regex, filepath))
        except re.error:
            return False

    def find_matching_sections(self, filepath: str) -> list[Section]:
        """Find all sections that match a given file path."""
        matching = []

        for section in self.sections:
            excluded = False

            # Check exclude patterns first
            for pattern, regex in section.excludes:
                if self.file_matches_pattern(filepath, pattern, regex):
                    excluded = True
                    break

            if excluded:
                continue

            # Check file patterns
            for pattern, regex in section.files:
                if self.file_matches_pattern(filepath, pattern, regex):
                    matching.append(section)
                    break
            else:
                # Check regex patterns (N: entries)
                for regex in section.regex_patterns:
                    try:
                        if re.search(regex, filepath):
                            matching.append(section)
                            break
                    except re.error:
                        pass

        return matching

    def get_files_from_patch(self, patch_path: str) -> list[str]:
        """Extract file paths from a patch file."""
        files = []
        fixes = []

        try:
            with open(patch_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    # diff --git a/file1 b/file2
                    match = re.match(r"^diff --git a/(\S+) b/(\S+)\s*$", line)
                    if match:
                        files.append(match.group(1))
                        files.append(match.group(2))
                        continue

                    # +++ b/file or --- a/file
                    match = re.match(r"^(?:\+\+\+|---)\s+[ab]/(.+)$", line)
                    if match:
                        files.append(match.group(1))
                        continue

                    # mode change
                    match = re.match(r"^ mode change [0-7]+ => [0-7]+ (\S+)\s*$", line)
                    if match:
                        files.append(match.group(1))
                        continue

                    # rename from/to
                    match = re.match(r"^rename (?:from|to) (\S+)\s*$", line)
                    if match:
                        files.append(match.group(1))
                        continue

                    # Fixes: tag
                    if self.config["email_fixes"]:
                        match = re.match(r"^Fixes:\s+([0-9a-fA-F]{6,40})", line)
                        if match:
                            fixes.append(match.group(1))

        except IOError as e:
            print(f"Error reading patch file: {e}", file=sys.stderr)
            return []

        # Remove duplicates while preserving order
        seen = set()
        unique_files = []
        for f in files:
            if f not in seen:
                seen.add(f)
                unique_files.append(f)

        return unique_files

    def add_email(self, email: str, role: str) -> None:
        """Add an email address to the results."""
        name, address = self.parse_email(email)

        if not address:
            return

        if address.lower() in [e.lower() for e in self.ignore_emails]:
            return

        formatted = self.format_email(name, address, self.config["email_usename"])

        # Check for duplicates
        if self.config["email_remove_duplicates"]:
            if name and name.lower() in self.email_hash_name:
                # Update role if needed
                for entry in self.email_to:
                    entry_name, _ = self.parse_email(entry.email)
                    if entry_name.lower() == name.lower():
                        if role and role not in entry.role:
                            if entry.role:
                                entry.role += f",{role}"
                            else:
                                entry.role = role
                        return
            if address.lower() in self.email_hash_address:
                for entry in self.email_to:
                    _, entry_addr = self.parse_email(entry.email)
                    if entry_addr.lower() == address.lower():
                        if role and role not in entry.role:
                            if entry.role:
                                entry.role += f",{role}"
                            else:
                                entry.role = role
                        return

        entry = MaintainerEntry(email=formatted, role=role)
        self.email_to.append(entry)

        if name:
            self.email_hash_name[name.lower()] = True
        self.email_hash_address[address.lower()] = True

    def add_list(self, list_addr: str, role: str) -> None:
        """Add a mailing list to the results."""
        # Parse list address and any additional info
        parts = list_addr.split(None, 1)
        address = parts[0]
        additional = parts[1] if len(parts) > 1 else ""

        # Check for subscribers-only or moderated lists
        if "subscribers-only" in additional:
            if not self.config["email_subscriber_list"]:
                return
            role = f"subscriber list:{role}" if role else "subscriber list"
        elif "moderated" in additional:
            if not self.config["email_moderated_list"]:
                return
            role = f"moderated list:{role}" if role else "moderated list"
        else:
            role = f"open list:{role}" if role else "open list"

        # Check for duplicates
        for entry in self.list_to:
            if entry.email.lower() == address.lower():
                return

        self.list_to.append(MaintainerEntry(email=address, role=role))

    def process_section(self, section: Section, suffix: str = "") -> None:
        """Process a matching section and add its entries."""
        subsystem_name = section.name
        if (self.config["output_section_maxlen"] and
                len(subsystem_name) > self.config["output_section_maxlen"]):
            subsystem_name = subsystem_name[:self.config["output_section_maxlen"] - 3] + "..."

        # Add maintainers
        if self.config["email_maintainer"]:
            for maintainer in section.maintainers:
                role = f"maintainer:{subsystem_name}{suffix}"
                self.add_email(maintainer, role)

        # Add reviewers
        if self.config["email_reviewer"]:
            for reviewer in section.reviewers:
                role = f"reviewer:{subsystem_name}{suffix}"
                self.add_email(reviewer, role)

        # Add mailing lists
        if self.config["email_list"]:
            for mailing_list in section.mailing_lists:
                role = subsystem_name if subsystem_name != "THE REST" else ""
                self.add_list(mailing_list, role + suffix)

        # Add SCM info
        if self.config["scm"]:
            for scm in section.scm:
                self.scm_list.append(scm + suffix)

        # Add web info
        if self.config["web"]:
            for web in section.web:
                self.web_list.append(web + suffix)

        # Add bug info
        if self.config["bug"]:
            for bug in section.bug:
                self.bug_list.append(bug + suffix)

        # Add subsystem
        if self.config["subsystem"]:
            self.subsystem_list.append(section.name + suffix)

        # Add status
        if self.config["status"] and section.status:
            self.status_list.append(section.status + suffix)

    def get_git_signers(self, filepath: str) -> list[tuple[str, int]]:
        """Get commit signers from git history for a file."""
        if self._detect_vcs() != "git":
            return []

        cmd = [
            "git", "log",
            "--no-color", "--follow",
            f"--since={self.config['email_git_since']}",
            "--numstat", "--no-merges",
            '--format=GitCommit: %H%nGitAuthor: %an <%ae>%nGitDate: %aD%nGitSubject: %s%n%b',
            "--", filepath
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=self.root_path
            )
            if result.returncode != 0:
                return []

            signers = defaultdict(int)
            signature_pattern = "|".join(re.escape(tag) for tag in SIGNATURE_TAGS)
            if self.config["email_git_all_signature_types"]:
                signature_pattern = r".+[Bb][Yy]:"

            for line in result.stdout.split("\n"):
                # Match author lines
                match = re.match(r"^GitAuthor:\s*(.+)$", line)
                if match:
                    email = self.deduplicate_email(match.group(1))
                    signers[email] += 1
                    continue

                # Match signature lines
                match = re.match(rf"^\s*({signature_pattern})\s*(.+@.+)$", line)
                if match:
                    email = self.deduplicate_email(match.group(2))
                    signers[email] += 1

            return sorted(signers.items(), key=lambda x: -x[1])

        except (subprocess.CalledProcessError, FileNotFoundError):
            return []

    def add_vcs_signers(self, filepath: str, exact_match: bool) -> None:
        """Add signers from git history."""
        if not self.config["email_git"]:
            if not (self.config["email_git_fallback"] and not exact_match):
                return

        if self._detect_vcs() != "git":
            return

        signers = self.get_git_signers(filepath)

        total_commits = sum(count for _, count in signers)
        if total_commits == 0:
            return

        added = 0
        for email, count in signers:
            if added >= self.config["email_git_max_maintainers"]:
                break
            if count < self.config["email_git_min_signatures"]:
                break

            percent = (count * 100) // total_commits
            if percent < self.config["email_git_min_percent"]:
                break

            if self.config["output_rolestats"]:
                role = f"commit_signer:{count}/{total_commits}={percent}%"
            else:
                role = "commit_signer"

            self.add_email(email, role)
            added += 1

    def find_maintainers(self, files: list[str]) -> None:
        """Find maintainers for the given files."""
        exact_matches = set()

        for filepath in files:
            matching_sections = self.find_matching_sections(filepath)

            # Track if we found an exact match
            for section in matching_sections:
                if section.status and "maintain" in section.status.lower():
                    if section.maintainers:
                        exact_matches.add(filepath)

            for section in matching_sections:
                self.process_section(section)

        # Add VCS signers
        if self.config["email"]:
            for filepath in files:
                exact_match = filepath in exact_matches
                self.add_vcs_signers(filepath, exact_match)

    def output_results(self) -> None:
        """Output the results."""
        results = []

        # Combine and deduplicate results
        seen_emails = set()

        if self.config["email"]:
            for entry in self.email_to + self.list_to:
                email_lower = entry.email.lower()
                if email_lower in seen_emails:
                    continue
                seen_emails.add(email_lower)

                if self.config["output_roles"] or self.config["output_rolestats"]:
                    results.append(f"{entry.email} ({entry.role})")
                else:
                    results.append(entry.email)

        # Output
        if self.config["output_multiline"]:
            for result in results:
                print(result)
        else:
            print(self.config["output_separator"].join(results))

        # Additional outputs
        if self.config["scm"]:
            for scm in sorted(set(self.scm_list)):
                print(scm)

        if self.config["status"]:
            for status in sorted(set(self.status_list)):
                print(status)

        if self.config["subsystem"]:
            for subsystem in sorted(set(self.subsystem_list)):
                print(subsystem)

        if self.config["web"]:
            for web in sorted(set(self.web_list)):
                print(web)

        if self.config["bug"]:
            for bug in sorted(set(self.bug_list)):
                print(bug)


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Find maintainers and mailing lists for patches or files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s patch.diff              Find maintainers for a patch
  %(prog)s -f drivers/net/foo.c    Find maintainers for a file
  %(prog)s --no-git patch.diff     Skip git history analysis

Default options:
  [--email --nogit --git-fallback --m --r --n --l --multiline
   --pattern-depth=0 --remove-duplicates --rolestats --keywords]
"""
    )

    parser.add_argument("files", nargs="*", help="Patch files or files to check")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {VERSION}")

    # Email options
    email_group = parser.add_argument_group("Email options")
    email_group.add_argument("--email", dest="email", action="store_true", default=True,
                            help="Print email addresses (default)")
    email_group.add_argument("--no-email", dest="email", action="store_false",
                            help="Don't print email addresses")
    email_group.add_argument("-m", dest="email_maintainer", action="store_true", default=True,
                            help="Include maintainers")
    email_group.add_argument("--no-m", dest="email_maintainer", action="store_false",
                            help="Exclude maintainers")
    email_group.add_argument("-r", dest="email_reviewer", action="store_true", default=True,
                            help="Include reviewers")
    email_group.add_argument("--no-r", dest="email_reviewer", action="store_false",
                            help="Exclude reviewers")
    email_group.add_argument("-n", dest="email_usename", action="store_true", default=True,
                            help="Include name in email")
    email_group.add_argument("--no-n", dest="email_usename", action="store_false",
                            help="Don't include name in email")
    email_group.add_argument("-l", dest="email_list", action="store_true", default=True,
                            help="Include mailing lists")
    email_group.add_argument("--no-l", dest="email_list", action="store_false",
                            help="Exclude mailing lists")
    email_group.add_argument("--moderated", dest="email_moderated_list", action="store_true", default=True,
                            help="Include moderated mailing lists")
    email_group.add_argument("--no-moderated", dest="email_moderated_list", action="store_false",
                            help="Exclude moderated mailing lists")
    email_group.add_argument("-s", dest="email_subscriber_list", action="store_true", default=False,
                            help="Include subscriber-only mailing lists")
    email_group.add_argument("--no-s", dest="email_subscriber_list", action="store_false",
                            help="Exclude subscriber-only mailing lists")
    email_group.add_argument("--remove-duplicates", dest="email_remove_duplicates",
                            action="store_true", default=True,
                            help="Remove duplicate email addresses")
    email_group.add_argument("--no-remove-duplicates", dest="email_remove_duplicates",
                            action="store_false",
                            help="Don't remove duplicate email addresses")
    email_group.add_argument("--mailmap", dest="email_use_mailmap", action="store_true", default=True,
                            help="Use .mailmap file")
    email_group.add_argument("--no-mailmap", dest="email_use_mailmap", action="store_false",
                            help="Don't use .mailmap file")
    email_group.add_argument("--fixes", dest="email_fixes", action="store_true", default=True,
                            help="Add signers from Fixes: commits")
    email_group.add_argument("--no-fixes", dest="email_fixes", action="store_false",
                            help="Don't add signers from Fixes: commits")

    # Git options
    git_group = parser.add_argument_group("Git options")
    git_group.add_argument("--git", dest="email_git", action="store_true", default=False,
                          help="Include recent git signers")
    git_group.add_argument("--no-git", dest="email_git", action="store_false",
                          help="Don't include git signers")
    git_group.add_argument("--git-fallback", dest="email_git_fallback", action="store_true", default=True,
                          help="Use git when no exact MAINTAINERS match")
    git_group.add_argument("--no-git-fallback", dest="email_git_fallback", action="store_false",
                          help="Don't use git fallback")
    git_group.add_argument("--git-all-signature-types", dest="email_git_all_signature_types",
                          action="store_true", default=False,
                          help="Include all signature types")
    git_group.add_argument("--git-blame", dest="email_git_blame", action="store_true", default=False,
                          help="Use git blame")
    git_group.add_argument("--no-git-blame", dest="email_git_blame", action="store_false",
                          help="Don't use git blame")
    git_group.add_argument("--git-min-signatures", type=int, default=1,
                          help="Minimum signatures required (default: 1)")
    git_group.add_argument("--git-max-maintainers", type=int, default=5,
                          help="Maximum maintainers to add (default: 5)")
    git_group.add_argument("--git-min-percent", type=int, default=5,
                          help="Minimum percentage of commits (default: 5)")
    git_group.add_argument("--git-since", default="1-year-ago",
                          help="Git history to use (default: 1-year-ago)")

    # Output options
    output_group = parser.add_argument_group("Output options")
    output_group.add_argument("--multiline", dest="output_multiline", action="store_true", default=True,
                             help="Print one entry per line (default)")
    output_group.add_argument("--no-multiline", dest="output_multiline", action="store_false",
                             help="Print all entries on one line")
    output_group.add_argument("--separator", dest="output_separator", default=", ",
                             help="Separator for single-line output (default: ', ')")
    output_group.add_argument("--roles", dest="output_roles", action="store_true", default=False,
                             help="Show roles")
    output_group.add_argument("--no-roles", dest="output_roles", action="store_false",
                             help="Don't show roles")
    output_group.add_argument("--rolestats", dest="output_rolestats", action="store_true", default=True,
                             help="Show roles and statistics (default)")
    output_group.add_argument("--no-rolestats", dest="output_rolestats", action="store_false",
                             help="Don't show role statistics")

    # Other options
    other_group = parser.add_argument_group("Other options")
    other_group.add_argument("-f", "--file", dest="from_filename", action="store_true", default=False,
                            help="Treat arguments as filenames, not patches")
    other_group.add_argument("--scm", action="store_true", default=False,
                            help="Print SCM information")
    other_group.add_argument("--no-scm", dest="scm", action="store_false",
                            help="Don't print SCM information")
    other_group.add_argument("--status", action="store_true", default=False,
                            help="Print status information")
    other_group.add_argument("--no-status", dest="status", action="store_false",
                            help="Don't print status information")
    other_group.add_argument("--subsystem", action="store_true", default=False,
                            help="Print subsystem name")
    other_group.add_argument("--no-subsystem", dest="subsystem", action="store_false",
                            help="Don't print subsystem name")
    other_group.add_argument("--web", action="store_true", default=False,
                            help="Print website information")
    other_group.add_argument("--no-web", dest="web", action="store_false",
                            help="Don't print website information")
    other_group.add_argument("--bug", action="store_true", default=False,
                            help="Print bug reporting information")
    other_group.add_argument("--no-bug", dest="bug", action="store_false",
                            help="Don't print bug reporting information")
    other_group.add_argument("-k", "--keywords", action="store_true", default=True,
                            help="Scan for keywords")
    other_group.add_argument("--no-keywords", dest="keywords", action="store_false",
                            help="Don't scan for keywords")
    other_group.add_argument("--pattern-depth", type=int, default=0,
                            help="Pattern directory traversal depth (default: 0 = all)")
    other_group.add_argument("--sections", action="store_true", default=False,
                            help="Print all matching sections")
    other_group.add_argument("--maintainer-path", "--mpath",
                            help="Path to MAINTAINERS file")

    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_args()

    # Build configuration from arguments
    config = DEFAULT_CONFIG.copy()
    for key in config:
        if hasattr(args, key):
            config[key] = getattr(args, key)

    # Handle special cases
    if args.output_separator != ", ":
        config["output_multiline"] = False

    if config["output_rolestats"]:
        config["output_roles"] = True

    # Create maintainer finder
    gm = GetMaintainer(config)

    # Load configuration files
    gm.load_ignore_file()
    if config["email_use_mailmap"]:
        gm.load_mailmap()

    # Load MAINTAINERS file
    if args.maintainer_path:
        gm.load_maintainers_file(Path(args.maintainer_path))
    else:
        gm.load_maintainers_file()

    # Get files to process
    if not args.files:
        if sys.stdin.isatty():
            print("Error: No files specified", file=sys.stderr)
            sys.exit(1)
        # Read from stdin
        args.files = ["-"]

    all_files = []
    for file_arg in args.files:
        if file_arg == "-":
            # Read patch from stdin
            import tempfile
            with tempfile.NamedTemporaryFile(mode="w", suffix=".patch", delete=False) as tmp:
                tmp.write(sys.stdin.read())
                tmp_path = tmp.name
            all_files.extend(gm.get_files_from_patch(tmp_path))
            os.unlink(tmp_path)
        elif args.from_filename:
            # Treat as file path
            all_files.append(file_arg)
        else:
            # Treat as patch file
            patch_files = gm.get_files_from_patch(file_arg)
            if not patch_files:
                print(f"Warning: '{file_arg}' doesn't appear to be a patch. Use -f to treat as file.",
                      file=sys.stderr)
            all_files.extend(patch_files)

    if not all_files:
        print("Error: No files found to process", file=sys.stderr)
        sys.exit(1)

    # Find maintainers
    gm.find_maintainers(all_files)

    # Output results
    gm.output_results()


if __name__ == "__main__":
    main()

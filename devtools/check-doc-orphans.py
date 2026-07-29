#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2026 Stephen Hemminger

"""
Report orphaned documentation source and image files.

Removing an example or a library leaves its images behind. Walk the doc
tree, build a reference graph from the Sphinx directives, roles and
toctrees, then list every text and image file that no longer has a path
from a documentation root.
"""

import argparse
import os
import re
import sys
from pathlib import Path

# Files reported when unreachable.
TEXT_SUFFIXES = {".rst"}
IMAGE_SUFFIXES = {".svg", ".png", ".jpg", ".jpeg", ".gif", ".dot"}
CANDIDATE_SUFFIXES = TEXT_SUFFIXES | IMAGE_SUFFIXES

# Files scanned for references but never reported. Build glue and
# configuration are always graph roots; .txt and .ini are generated or
# picked up by wildcard (nics/features/*.ini), so the absence of a
# reference to them means nothing.
ROOT_SUFFIXES = {".py", ".build", ".md", ".in", ".css", ".txt", ".ini"}

# Kept on purpose although the documentation build has no use for them.
# The horizontal logo is used outside the repository. Paths are relative
# to the documentation directory.
IGNORE = {"logo/DPDK_logo_horizontal_tag.png"}

# Directives whose argument is a file name.
DIRECTIVE_RE = re.compile(
    r"^\s*\.\.\s+"
    r"(?:figure|image|include|literalinclude|graphviz)"
    r"::\s*(\S.*?)\s*$"
)
# Directive option naming a file, such as the :file: of csv-table.
OPTION_RE = re.compile(r"^\s*:file:\s*(\S+)\s*$")
# Cross reference to another document or to a downloadable file.
ROLE_RE = re.compile(r":(?:doc|download):`([^`]*)`")
TOCTREE_RE = re.compile(r"^(\s*)\.\.\s+toctree::\s*$")
# Bare path in a non-rst file, such as html_logo in conf.py.
PATH_RE = re.compile(
    r"[\w./-]+\.(?:" + "|".join(s[1:] for s in sorted(CANDIDATE_SUFFIXES)) + r")\b"
)


def toctree_entries(lines):
    """Yield the document names listed in every toctree block."""
    i = 0
    while i < len(lines):
        match = TOCTREE_RE.match(lines[i])
        i += 1
        if not match:
            continue
        outer = len(match.group(1))
        while i < len(lines):
            line = lines[i]
            if line.strip() and len(line) - len(line.lstrip()) <= outer:
                break
            entry = line.strip()
            if entry and not entry.startswith(":"):
                yield entry
            i += 1


def targets(path):
    """Yield the raw reference targets found in one file."""
    if path.suffix in IMAGE_SUFFIXES:
        return  # image metadata names unrelated files
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as err:
        sys.exit(f"{path}: {err.strerror}")
    if path.suffix not in TEXT_SUFFIXES:
        yield from PATH_RE.findall(text)
        return
    lines = text.splitlines()
    for line in lines:
        match = DIRECTIVE_RE.match(line) or OPTION_RE.match(line)
        if match:
            yield match.group(1)
    for match in ROLE_RE.finditer(text):
        yield match.group(1)
    for entry in toctree_entries(lines):
        # A toctree entry has no suffix, and :glob: allows patterns.
        yield entry if "*" in entry else entry + ".rst"


def resolve(target, path, srcdir):
    """Yield the files one target can refer to."""
    # Roles use "title <target>", docutils includes use <standard.txt>.
    if target.endswith(">"):
        target = target[target.rfind("<") + 1 : -1]
    if not target or target.startswith(("http:", "https:", "mailto:")):
        return
    # A leading / is relative to the Sphinx source directory.
    base = srcdir if target.startswith("/") else path.parent
    target = target.lstrip("/")
    if "*" in target:
        yield from (found.resolve() for found in base.glob(target))
    else:
        yield (base / target).resolve()


def collect(docdir):
    """Return the candidate files, the graph roots and the source dirs."""
    candidates, roots, srcdirs = set(), set(), set()
    for dirpath, dirnames, filenames in os.walk(docdir):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        here = Path(dirpath).resolve()
        for name in filenames:
            path = here / name
            if path.suffix in CANDIDATE_SUFFIXES:
                candidates.add(path)
            elif path.suffix in ROOT_SUFFIXES:
                roots.add(path)
        # A directory built by sphinx-build is a documentation root.
        # Sphinx starts from index.rst there whether meson names it or not.
        build = here / "meson.build"
        if not build.is_file():
            continue
        if "sphinx" in build.read_text(encoding="utf-8", errors="replace"):
            srcdirs.add(here)
            if (here / "index.rst").is_file():
                roots.add(here / "index.rst")
    return candidates, roots, srcdirs


def walk_graph(candidates, roots, srcdirs, docdir):
    """Return the reachable files, and the targets that do not exist."""
    missing = {}
    seen = set()
    queue = list(roots)
    while queue:
        path = queue.pop()
        if path in seen:
            continue
        seen.add(path)
        srcdir = next((p for p in path.parents if p in srcdirs), docdir)
        for target in targets(path):
            for hit in resolve(target, path, srcdir):
                if hit in candidates or hit in roots:
                    queue.append(hit)
                elif hit.suffix in CANDIDATE_SUFFIXES and not hit.is_file():
                    missing.setdefault(hit, path)
    return seen, missing


def main():
    """Scan the doc tree and report what nothing refers to."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "docdir", nargs="?", type=Path, help="documentation directory (default: ../doc)"
    )
    parser.add_argument(
        "-a",
        "--all",
        action="store_true",
        help="include the files that are ignored on purpose",
    )
    parser.add_argument(
        "-m",
        "--missing",
        action="store_true",
        help="also report references to files not present",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="report the number of files examined",
    )
    args = parser.parse_args()

    docdir = args.docdir or Path(__file__).resolve().parent.parent / "doc"
    if not docdir.is_dir():
        sys.exit(f"{docdir}: not a directory")
    docdir = docdir.resolve()
    top = docdir.parent

    candidates, roots, srcdirs = collect(docdir)
    if not srcdirs:
        sys.exit(f"{docdir}: no sphinx source directory found")

    seen, missing = walk_graph(candidates, roots, srcdirs, docdir)
    if not args.all:
        seen |= {docdir / name for name in IGNORE}
    unused = sorted(candidates - seen)

    for path in unused:
        print(f"orphan {path.relative_to(top)}")
    if args.missing:
        for path, referrer in sorted(missing.items()):
            print(
                f"missing {path.relative_to(top)} "
                f"(referenced by {referrer.relative_to(top)})"
            )
    if args.verbose:
        print(
            f"{len(candidates)} files examined, {len(unused)} orphaned", file=sys.stderr
        )
    return 1 if unused or (args.missing and missing) else 0


if __name__ == "__main__":
    sys.exit(main())

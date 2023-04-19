#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2023 Stephen Hemminger
#
# This script scans the source tree and creates list of files
# containing words that are recommended to avoided by the
# Inclusive Naming Initiative.
# See: https://inclusivenaming.org/word-lists/

"""Script to run git grep to finds strings in inclusive naming word list."""

import argparse
import json
import subprocess
import sys
from urllib.request import urlopen

WORDLIST_URL = 'https://inclusivenaming.org/word-lists/index.json'

# These give false positives
dont_scan = [
    'doc/guides/rel_notes/',
    'doc/guides/contributing/coding_style.rst'
    'doc/guides/prog_guide/glossary.rst'
]


def args_parse():
    "parse arguments and return the argument object back to main"

    parser = argparse.ArgumentParser(
        description="Identify word usage not aligned with inclusive naming")
    parser.add_argument("-c",
                        "--count",
                        help="Show the number of lines that match",
                        action='store_true')
    parser.add_argument("-d",
                        "--debug",
                        default=False,
                        help="Debug this script",
                        action='store_true')
    parser.add_argument("-l",
                        "--files-with-matches",
                        help="Show only names of files with hits",
                        action='store_true')
    parser.add_argument("-n",
                        "--line-number",
                        help="Prefix with line number to matching lines",
                        action='store_true')
    # note: tier 0 is "OK to use"
    parser.add_argument("-t",
                        "--tier",
                        type=int,
                        choices=range(0, 4),
                        action='append',
                        help="Show non-conforming words of particular tier")
    parser.add_argument('-x',
                        "--exclude",
                        default=dont_scan,
                        action='append',
                        help="Exclude path from scan")
    parser.add_argument('--url',
                        default=WORDLIST_URL,
                        help="URL for the non-inclusive naming word list")
    parser.add_argument('paths', nargs='*',
                        help='files and directory to scan')

    return parser.parse_args()


def fetch_wordlist(url, tiers):
    "Read list of words from inclusivenaming.org"

    # The word list is returned as JSON like:
    # {
    # "data" :
    #         [
    #             {
    #                 "term": "abort",
    #                 "tier" : "1",
    #                 "recommendation": "Replace when possible.",
    # ...
    with urlopen(url) as response:
        entries = json.loads(response.read())['data']

    wordlist = []
    for item in entries:
        tier = int(item['tier'])
        if tiers.count(tier) > 0:
            # convert minus sign to minus or space regex
            pattern = item['term'].replace('-', '[- ]')
            wordlist.append(pattern.lower())
    return wordlist


def git_args(args):
    "Construct command line based on args"

    # Default to Tier 1, 2 and 3.
    if args.tier:
        tiers = args.tier
    else:
        tiers = list(range(1, 4))

    wordlist = fetch_wordlist(args.url, tiers)
    if args.debug:
        print(f"Matching on: {wordlist}")

    cmd = ['git', 'grep', '-i']
    if args.files_with_matches:
        cmd.append('-l')
    if args.count:
        cmd.append('-c')
    if args.line_number:
        cmd.append('-n')
    for word in wordlist:
        cmd.append('-e')
        cmd.append(word)
    cmd.append('--')
    # convert the dont_scan paths to regexp
    for path in dont_scan:
        cmd.append(f":^{path}")
    cmd += args.paths
    if args.debug:
        print(cmd)
    return cmd


def main():
    "decode command line arguments then run setup to run"

    grep = subprocess.run(git_args(args_parse()), check=False)
    sys.exit(grep.returncode)


if __name__ == "__main__":
    main()

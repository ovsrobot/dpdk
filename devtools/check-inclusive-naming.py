#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2023 Stephen Hemminger
#
# This script scans the source tree and creates list of files
# containing words that are recommended to bavoide by the
# Inclusive Naming Initiative.
# See: https://inclusivenaming.org/word-lists/

import argparse
import subprocess
from urllib.request import urlopen
import json

naming_url = 'https://inclusivenaming.org/word-lists/index.json'

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
                        help="Show the nuber of lines that match",
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
    # note: tier 0 is "ok to use"
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
                        default=naming_url,
                        help="URL for the non-inclusive naming word list")
    parser.add_argument('paths', nargs='*',
                        help='files and directory to scan')

    return parser.parse_args()


def fetch_wordlist(url, tiers):
    "Read list of words from inclusivenaming.org"

    response = urlopen(url)
    # The wordlist is returned as JSON like:
    # {
    # "data" :
    #         [
    #             {
    #                 "term": "abort",
    #                 "tier" : "1",
    #                 "recommendation": "Replace when possible.",
    # ...
    entries = json.loads(response.read())['data']

    wordlist = []
    for item in entries:
        tier = int(item['tier'])
        if (tiers.count(tier) > 0):
            # convert minus sign to minus or space regex
            pattern = item['term'].replace('-', '[- ]')
            wordlist.append(pattern.lower())
    return wordlist


def process(args):
    "Find matching words"

    # Default to Tier 1, 2 and 3.
    if (args.tier):
        tiers = args.tier
    else:
        tiers = list(range(1, 4))

    wordlist = fetch_wordlist(args.url, tiers)
    if (args.debug):
        print("Matching on {} words".format(len(wordlist)))

    cmd = ['git', 'grep', '-i']
    if (args.files_with_matches):
        cmd.append('-l')
    if (args.count):
        cmd.append('-c')
    for word in wordlist:
        cmd.append('-e')
        cmd.append(word)
    cmd.append('--')
    # convert the dont_scan paths to regexp
    for path in dont_scan:
        cmd.append(':^{}'.format(path))
    cmd += args.paths
    if args.debug:
        print(cmd)
    subprocess.run(cmd)


def main():
    process(args_parse())


if __name__ == "__main__":
    main()

#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 Neil Horman <nhorman@tuxdriver.com>

build_map_changes()
{
	local fname="$1"
	local mapdb="$2"

	cat "$fname" | awk '
		# Initialize our variables
		BEGIN {map="";sym="";ar="";sec=""; in_sec=0; in_map=0}

		# Anything that starts with + or -, followed by an a
		# and ends in the string .map is the name of our map file
		# This may appear multiple times in a patch if multiple
		# map files are altered, and all section/symbol names
		# appearing between a triggering of this rule and the
		# next trigger of this rule are associated with this file
		/[-+] [ab]\/.*\.map/ {map=$2; in_map=1; next}

		# The previous rule catches all .map files, anything else
		# indicates we left the map chunk.
		/[-+] [ab]\// {in_map=0}

		# Triggering this rule, which starts a line and ends it
		# with a { identifies a versioned section.  The section name is
		# the rest of the line with the + and { symbols removed.
		# Triggering this rule sets in_sec to 1, which actives the
		# symbol rule below
		/^.*{/ {
			gsub("+", "");
			if (in_map == 1) {
				sec=$(NF-1); in_sec=1;
			}
		}

		# This rule identifies the end of a section, and disables the
		# symbol rule
		/.*}/ {in_sec=0}

		# This rule matches on a + followed by any characters except a :
		# (which denotes a global vs local segment), and ends with a ;.
		# The semicolon is removed and the symbol is printed with its
		# association file name and version section, along with an
		# indicator that the symbol is a new addition.  Note this rule
		# only works if we have found a version section in the rule
		# above (hence the in_sec check) And found a map file (the
		# in_map check).  If we are not in a map chunk, do nothing.  If
		# we are in a map chunk but not a section chunk, record it as
		# unknown.
		/^+[^}].*[^:*];/ {gsub(";","");sym=$2;
			if (in_map == 1) {
				if (in_sec == 1) {
					print map " " sym " " sec " add"
				} else {
					print map " " sym " unknown add"
				}
			}
		}

		# This is the same rule as above, but the rule matches on a
		# leading - rather than a +, denoting that the symbol is being
		# removed.
		/^-[^}].*[^:*];/ {gsub(";","");sym=$2;
			if (in_map == 1) {
				if (in_sec == 1) {
					print map " " sym " " sec " del"
				} else {
					print map " " sym " unknown del"
				}
			}
		}' > "$mapdb"

		sort -u "$mapdb" > "$mapdb.2"
		mv -f "$mapdb.2" "$mapdb"
}

#!/bin/bash

dpdk_dir=$(git rev-parse --show-toplevel)
if [ -z "$dpdk_dir" ]; then
  echo "Please execute this script from within a git repo"
  exit 1
fi

set -e
allowed_words=''  # path to allowed words file
all_check='false' # optional flag to check all documentation
verbose_logging='false'
branch=$(git rev-parse --abbrev-ref HEAD) # Gets current working branch
regex_dir=''

while test $# -gt 0; do
	case "$1" in
	-h | --help)
		echo "Spell Check"
		echo " "
		echo "spell_check [options] [arguments]"
		echo " "
		echo "options:"
		echo "-h, --help
			Show shows list of flags and usages."
		echo "-a, --all-doc
			Specify if all documentation should be checked."
		echo "-b
			Specify a different branch to be checked against."
		echo "-d
			Specify a different dictionary to be used by aspell."
		echo "-o, --output-dir=DIR
			Specify a directory to store output in."
		echo "-r
			Specify a different regex pattern file."
		echo "-v
			Specify verbose logging."
		exit 0
		;;
	-a | --all-doc)
		shift
		export all_check='true'
		;;
	-b)
		shift
		export remote_branch=$1
		shift
		;;
	-r)
		shift
		export regex_dir=$1
		shift
		;;
	-d)
		shift
		export allowed_words=$1
		shift
		;;
	-v)
		shift
		echo "Verbose logging active!"
		export verbose_logging='true'
		;;
	-o)
		shift
		if test $# -gt 0; then
			export output=$1
		else
			echo "no output dir specified"
			exit 1
		fi
		shift
		;;
	--output-dir*)
		export output=$(echo $1 | sed -e 's/^[^=]*=//g')
		shift
		;;
	*)
		break
		;;
	esac
done

if [ "" = "$output" ]; then
	output="$dpdk_dir/devtools/spell_check.log"
else
	output+=/spell_check.log
fi

if [ "" = "$regex_dir" ]; then
	regex_dir="$dpdk_dir/devtools/spell_check_regex.txt"
fi

PKG_OK=$(which aspell)

if [ $verbose_logging = 'true' ]; then
	echo Checking for Aspell: "$PKG_OK"
fi

if [ "" = "$PKG_OK" ]; then
	echo "Missing Required Package: Aspell"
	exit 1
fi

PKG_OK=$(which git)

if [ $verbose_logging = 'true' ]; then
	echo Checking for Git: "$PKG_OK"
fi

if [ "" = "$PKG_OK" ]; then
	echo "Missing Required Package: Git"
	exit 1
fi

PKG_OK=$(which parallel)

if [ $verbose_logging = 'true' ]; then
	echo Checking for Parallel: "$PKG_OK"
fi

if [ "" = "$PKG_OK" ]; then
	echo "Missing Required Package: Parallel"
	exit 1
fi

# Checking if remote branch flag was set
if [ "" = "$remote_branch" ]; then
	remote_branch=$branch
fi

# Checking if separate dictionary was supplied, if not defaults to
# spell_check_dictionary.txt in current dir
if [ "" = "$allowed_words" ]; then
	allowed_words=$dpdk_dir'/devtools/spell_check_dictionary.txt'
fi

# function to spell check a single file
function spellcheck_file() {
	file="$3/$1"
	dictionary="$2"
	sed -e "$4" "$file" | # used to simplify lines sent to aspell
	  tr -d '*' |
	  tr -d '`' |
	  aspell --lang=en --encoding=utf-8 --ignore-case \
	  --ignore-repl pipe list -d en --ignore=3 --personal="$dictionary" |
	  sed -r '/\*/d; /^\s*$/d' |
	  cut -d ' ' -f 2 |
	  sort -u |
	  sed '/International/d' |
	  grep -Z "" |
	  xargs -0 -I % grep -on "%" "$file" |
	  awk -v file="$file" -F ':' '{ printf "%s:%s %s\n", file, $1, $2 }'
}

# Build regex pattern from files
regex_pattern="'s/(R)//; "
while IFS= read -r line; do
  if [[ ! $line =~ "#" ]]; then
    regex_pattern+="s/$line/ /; "
  fi
done < "$regex_dir"
regex_pattern="${regex_pattern::-1}'"

if [ "'" = "$regex_pattern" ]; then
  regex_pattern=''
fi

# Make sure output file is present and empty
touch "$output"
truncate -s 0 "$output"

# setup so that parallel can use the function
export -f spellcheck_file
export SHELL="$(type -p bash)"

# Compares diff between current branch and it's remote counterpart
if [ ! $all_check = 'true' ]; then
  git diff "$branch" origin/"$remote_branch" --name-only |
	  grep ".*\.rst" |
	  # run the spellcheck function over each file in parallel, appending
	  # misspellings to the output file
	  parallel -j "$(nproc)" spellcheck_file {} "$allowed_words" "$dpdk_dir" \
	  "$regex_pattern" >> "$output"
  else
    cd "$dpdk_dir"
    find . -name "*.rst" -type f | parallel -j "$(nproc)" spellcheck_file {} \
    "$allowed_words" "$dpdk_dir" "$regex_pattern" >>"$output"
fi


cat "$output"

# remove empty lines in the output
sed -i '/^$/d' "$output"

# Errors can be counted by counting the number of lines in the output
errors="$(wc -l "$output" | cut -d ' ' -f 1)"
printf "Errors found: %d\n" "$errors" | tee -a "$output"

# Make the exit code the number of errors
exit "$errors"

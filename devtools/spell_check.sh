#!/bin/bash

file_count=0
error_count=0
non_doc=0
simple_out=''
output_dir=''
regex_pattern=''
output=''
dir=$(git rev-parse --show-toplevel)
if [ -z "$dir" ]; then
  echo "Please execute this script from within a git repo"
  exit 1
fi

# Function to spell check a single file
function spellcheck() {
	echo "$3" | sed "$2" | aspell --lang=en \
				      --encoding=utf-8 \
				      --ignore-case \
				      --ignore=3 \
				      --ignore-repl \
				      list \
				      --personal="$1""/devtools/spell_check_dictionary.txt"
}

function read_input {
  while read -r data; do
    echo "$data"
  done
}

while test $# -gt 0; do
	case "$1" in
	-h | --help)
		echo "Spell Check"
		echo " "
		echo "spell_check [options] [arguments]"
		echo " "
		echo "options:"
		echo "-h, --help    Show shows list of flags and usages."
		echo "-e            Excludes file (and dir) from being printed."
		echo "-output-dir=            Output file."
		exit 0
		;;
	-e)
		shift
		export simple_out='true'
		;;
	--output-dir*)
		export output_dir=$(echo $1 | sed -e 's/^[^=]*=//g')
		shift
		;;
	*)
		break
		;;
	esac
done

# Requires patch file be piped into script
PATCH_FILE=$(read_input)
PATCH_FILE=$(echo "$PATCH_FILE" | sed 's/``.*``//' | grep ^+ | tr -d '*')

# Build regex pattern from files
while IFS= read -r line; do
  if [[ ! $line =~ "#" ]]; then
    regex_pattern+="s/$line/ /; "
  fi
done < "$dir/devtools/spell_check_regex.txt"

if [ -n "$regex_pattern" ]; then
  regex_pattern="${regex_pattern::-1}"
fi

if [ 's// /;' = "$regex_pattern" ]; then
  regex_pattern=''
fi


while IFS= read -r line; do
  if [[ ($line =~ ^\+\+\+) && ($line =~ .rst$)]]; then
    output=$output"${line//+++ b\//}"$'\n'
    ((file_count=file_count+1))
    non_doc=0
    continue
  elif [[ ($line =~ ^\+\+\+) && (! $line =~ .rst$)]]; then
    non_doc=1
    continue;
  fi

  if [[ ($non_doc = 0 ) && (! $line =~ ^\+\+\+)]]; then
    line=${line/+  /}
    line=${line/+/}
    for word in $line;
    do
	error=$(spellcheck "$dir" "$regex_pattern" "$(echo "$word" |
	sed 's/>/ /;
	     s/</ /;
	     s/:/ /;
	     s/:/ /;
	     s/\*/ /;
	     s/\+/ /;
	     s/`/ /;
	     s/"/ /;')")

	if [ -n "$error" ]; then
	  output=$output$error$'\n'
	  ((error_count=error_count+1))
	fi
    done
  fi
done <<< "$PATCH_FILE"

if [ -z "$simple_out" ]; then
      echo "$output""Errors: $error_count"
elif [ -n "$output_dir" ]; then
  touch "$output_dir"
  echo "$output""Errors: $error_count"$'\n' >> "$output_dir"
fi

exit 0

#!/bin/sh
# Print the license texts of every third-party Go module compiled into a
# binary, for THIRD_PARTY_NOTICES in release archives. Reads the module list
# from the binary itself (go version -m), so it can't drift from what ships.
# Fails if a module has no license file.
#
# Usage: scripts/third-party-notices.sh path/to/binary > THIRD_PARTY_NOTICES
set -eu

bin="$1"
deps=$(go version -m "$bin" | awk '$1 == "dep" { print $2 "@" $3 }')

echo "Third-party software included in hextrap-artifacts"
echo "==================================================="
for dep in $deps; do
	dir=$(go mod download -json "$dep" | sed -n 's/^[[:space:]]*"Dir": "\(.*\)",$/\1/p')
	licenses=$(find "$dir" -maxdepth 1 -type f \( -iname 'LICENSE*' -o -iname 'LICENCE*' -o -iname 'COPYING*' -o -iname 'NOTICE*' \) | sort)
	if [ -z "$licenses" ]; then
		echo "no license file found for $dep in $dir" >&2
		exit 1
	fi
	echo
	echo "-------------------------------------------------------------------"
	echo "$dep"
	echo "-------------------------------------------------------------------"
	for f in $licenses; do
		echo
		cat "$f"
	done
done

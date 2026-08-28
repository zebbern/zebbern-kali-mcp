#!/bin/sh
set -eu

url=$1
ref=$2
destination=$3

test ! -e "$destination"
git init -q "$destination"
git -C "$destination" remote add origin "$url"
git -C "$destination" fetch -q --depth 1 origin "$ref"
git -C "$destination" checkout -q --detach FETCH_HEAD
actual=$(git -C "$destination" rev-parse HEAD)
test "$actual" = "$ref"
printf '%s\n' "$actual" > "$destination/.source-ref"
rm -rf "$destination/.git"

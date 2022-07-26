#!/bin/bash

set -eu
here="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

printf "=> Checking for unacceptable language... "
# This greps for unacceptable terminology. The square bracket[s] are so that
# "git grep" doesn't find the lines that greps :).
# We exclude the vendored BoringSSL copy from this check.
unacceptable_terms=(
    -e blacklis[t]
    -e whitelis[t]
    -e slav[e]
    -e sanit[y]
)
if git grep --color=never -i "${unacceptable_terms[@]}" ':(exclude)Sources/CMiniRSACryptBoringSSL*' > /dev/null; then
    printf "\033[0;31mUnacceptable language found.\033[0m\n"
    git grep -i "${unacceptable_terms[@]}" ':(exclude)Sources/CMiniRSACryptBoringSSL*'
    exit 1
fi
printf "\033[0;32mokay.\033[0m\n"

printf "=> Checking format\n"
FIRST_OUT="$(git status --porcelain)"
# only checking directory named BoringSSL, rest is shared code and we need to preserve original format
shopt -u dotglob
find Sources/* Tests/* -name BoringSSL -type d | while IFS= read -r d; do
  printf "   * checking $d... "
  out=$(swiftformat "$d" 2>&1)
  SECOND_OUT="$(git status --porcelain)"
  if [[ "$out" == *"error"*] && ["$out" != "*No eligible files" ]]; then
    printf "\033[0;31merror!\033[0m\n"
    echo $out
    exit 1
  fi
  if [[ "$FIRST_OUT" != "$SECOND_OUT" ]]; then
    printf "\033[0;31mformatting issues!\033[0m\n"
    git --no-pager diff
    exit 1
  fi
  printf "\033[0;32mokay.\033[0m\n"
done

printf "=> Checking #defines..."
if grep 'development = true' Package.swift > /dev/null; then
  printf "\033[0;31mstill in development mode!\033[0m\n"
  exit 1
else
  printf "\033[0;32mokay.\033[0m\n"
fi

#!/bin/sh
# Allows you to override this variable with CLANG_FORMAT=$(which clang-format) ./clang-format.sh
: ${CLANG_FORMAT:="$(which clang-format)"}

if [[ ! -f "$CLANG_FORMAT" ]]
then
  echo "Not found: $CLANG_FORMAT"
  exit 1
fi

# Reference: https://gist.github.com/Ortham/d55e58c61c2191295b11bf19c99db202
echo "$CLANG_FORMAT -style=file -i \$(git ls-files *.c *.h *.cpp *.hpp)"
"$CLANG_FORMAT" -style=file -i $(git ls-files *.c *.h *.cpp *.hpp)
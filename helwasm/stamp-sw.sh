#!/bin/sh
# Generate helwasm/sw.js from helwasm/sw.template.js, stamping VERSION with a
# content hash of the shipped shell. The browser runs its service-worker update
# check exactly when these bytes change (and never needlessly). Run by build.sh,
# or standalone to regenerate sw.js after an HTML/CSS/SW change without a wasm
# rebuild. Both template and generated sw.js are committed (no CI).
set -e
cd "$(dirname "$0")/.."

VER="$(find helwasm -type f \
         \( -name '*.html' -o -name '*.css' -o -name '*.js' -o -name '*.wasm' \
            -o -name '*.woff2' -o -name '*.png' -o -name '*.ico' -o -name '*.svg' \
            -o -name '*.webmanifest' \) \
         ! -path '*/my-app/*' ! -name 'sw.js' -print0 \
       | LC_ALL=C sort -z | xargs -0 shasum -a 256 | shasum -a 256 | cut -c1-12)"

sed "s/__VERSION__/$VER/" helwasm/sw.template.js > helwasm/sw.js
echo "stamped helwasm/sw.js version=$VER"

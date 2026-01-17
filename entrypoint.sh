#!/usr/bin/env bash

set -eEuo pipefail

rm -rf public
mkdir -p public
touch public/.gitkeep

pandoc index.md -o /tmp/index.html \
  --toc --standalone -c styles.css \
  --filter /opt/pandoc-crossref/pandoc-crossref \
  --extrac-media="public/images"

sed 's#src="public/images/images/#src="images/#g' /tmp/index.html > public/index.html

echo "OK"

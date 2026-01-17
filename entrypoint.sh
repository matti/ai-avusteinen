#!/usr/bin/env bash

set -eEuo pipefail

pandoc index.md -o public/index.html \
  --toc --standalone -c styles.css \
  --filter /opt/pandoc-crossref/pandoc-crossref

echo "OK"

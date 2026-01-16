#!/usr/bin/env bash

set -eEuo pipefail

pandoc ai.md -o ai.html --toc --standalone -c styles.css --filter /opt/pandoc-crossref/pandoc-crossref

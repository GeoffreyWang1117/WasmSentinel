#!/usr/bin/env bash
# Fetch the raw datasets used under evaluation/ into evaluation/datasets/raw/ (git-ignored).
# Each repository is pinned to the exact commit that this repo previously vendored as a gitlink,
# so results stay comparable across machines.
#
# Usage: scripts/fetch_datasets.sh [ADFA-LD] [LID-DS]   (default: both)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RAW="$ROOT/evaluation/datasets/raw"
mkdir -p "$RAW"

fetch() {
  local name="$1" url="$2" sha="$3" dst="$RAW/$1"
  if [ -d "$dst/.git" ]; then
    echo "[skip ] $name already cloned at $dst"
  else
    echo "[clone] $name <- $url"
    git clone --quiet "$url" "$dst"
  fi
  git -C "$dst" fetch --quiet origin "$sha" 2>/dev/null || true
  git -C "$dst" checkout --quiet "$sha"
  echo "[ok   ] $name @ $(git -C "$dst" rev-parse --short HEAD)  ($(du -sh "$dst" | cut -f1))"
}

want="${*:-ADFA-LD LID-DS}"
for ds in $want; do
  case "$ds" in
    ADFA-LD)
      # Creech & Hu (2013). Labelled re-distribution, ~30 MB.
      fetch ADFA-LD https://github.com/verazuo/a-labelled-version-of-the-ADFA-LD-dataset.git \
            68bedf561f7b7abe9954a3ddc22dbf24c0d42372 ;;
    LID-DS)
      # Grimmer et al. LID-DS *framework* (scenario code, ~480 MB). The recorded 2019/2021
      # system-call traces are a separate download; see the upstream README.
      fetch LID-DS https://github.com/LID-DS/LID-DS.git \
            587d15870843961acb78fbb4b8fcd0ede28eabcc ;;
    *) echo "unknown dataset: $ds (choose ADFA-LD or LID-DS)" >&2; exit 2 ;;
  esac
done

#!/usr/bin/env bash
set -euo pipefail

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  exit 0
fi

echo "[run-safety-checks] Recent changes by Claude:"
git diff --stat

if command -v detect-secrets >/dev/null 2>&1; then
  echo "[run-safety-checks] Running detect-secrets scan..."
  detect-secrets scan > .secrets.baseline.tmp || true
  echo "[run-safety-checks] Scan finished. Review .secrets.baseline.tmp if needed."
fi

exit 0

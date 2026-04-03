#!/usr/bin/env bash
set -euo pipefail

TARGET_PATH="${CLAUDE_FILE_PATH:-}"
TARGET_BASENAME="$(basename "$TARGET_PATH")"

if [[ -z "$TARGET_PATH" ]]; then
  echo "Blocked by protect-files.sh: CLAUDE_FILE_PATH was empty — blocking as a precaution" >&2
  exit 2
fi

block() {
  echo "Blocked by protect-files.sh: $1" >&2
  exit 2
}

if [[ "$TARGET_PATH" =~ (^|/)\.env($|\.) ]]; then
  block "access to .env or .env.* files is not allowed"
fi
if [[ "$TARGET_PATH" == *"/secrets/"* ]]; then
  block "access to secrets/ directory is not allowed"
fi
if [[ "$TARGET_PATH" == *"/.aws/"* ]] || [[ "$TARGET_PATH" == *"/.ssh/"* ]]; then
  block "access to .aws/ or .ssh/ directories is not allowed"
fi
if [[ "$TARGET_BASENAME" == id_rsa* ]] || [[ "$TARGET_BASENAME" == *_rsa ]] \
   || [[ "$TARGET_BASENAME" == *_dsa ]] || [[ "$TARGET_BASENAME" == *_ed25519 ]]; then
  block "access to SSH private key material is not allowed"
fi
if echo "$TARGET_BASENAME" | grep -qiE 'key|secret|token|password|credential|cert'; then
  block "access to files with sensitive names is not allowed"
fi
if [[ "$TARGET_PATH" == *"/.git/"* ]] || [[ "$TARGET_PATH" == *"/.github/"* ]]; then
  block "access to .git/.github is not allowed"
fi

exit 0

#!/usr/bin/env bash
set -euo pipefail

INPUT=$(cat)
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty')

block() {
  echo "Blocked by validate-commands.sh: $1" >&2
  exit 2
}

if echo "$COMMAND" | grep -qE '(>>|>).*\.env'; then
  block "bash write to .env file detected"
fi
if echo "$COMMAND" | grep -qE 'rm\s+-rf\s+(/|\*)'; then
  block "dangerous rm -rf detected"
fi
if echo "$COMMAND" | grep -qE '\|\s*(sh|bash|zsh)'; then
  block "pipe-to-shell pattern detected"
fi
if echo "$COMMAND" | grep -qiE '(DROP\s+TABLE|DELETE\s+FROM)'; then
  block "SQL injection pattern detected"
fi
if echo "$COMMAND" | grep -qiE 'pg_dump|mysqldump|mongoexport|mongodump'; then
  block "database dump commands are not allowed from Claude"
fi
if echo "$COMMAND" | grep -qiE 'tar\s+.*(cvf|czf|xf)\s+.*\.(tar|tar\.gz|tgz|zip)'; then
  block "creating large archives from Claude is not allowed"
fi
if echo "$COMMAND" | grep -qiE 'cp\s+-r\s+(\.aws|\.ssh|\.git|secrets)'; then
  block "copying sensitive directories is not allowed"
fi
if echo "$COMMAND" | grep -qiE '(curl|wget)\s+.*(http|https)'; then
  block "network transfer via curl/wget not allowed from Claude"
fi
if echo "$COMMAND" | grep -qiE 'git\s+push'; then
  block "git push from Claude is not allowed"
fi
if echo "$COMMAND" | grep -qiE 'rm\s+-rf\s+\.?dist'; then
  block "high-risk cleanup blocked for Claude; run manually"
fi
if echo "$COMMAND" | grep -qiE '\b(scp|rsync|nc|ncat|netcat)\b'; then
  block "network file transfer or raw socket tool not allowed from Claude"
fi

exit 0

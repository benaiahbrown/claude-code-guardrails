# Security Policy

## 1. Secrets and Sensitive Files
- Never read, write, or suggest operations on files that may contain credentials or secrets, including: `.env`, `.env.*`, `secrets/`, `.aws/`, `.ssh/`, `.git/`, `.github/`, any file with `key`, `secret`, `token`, `password`, `credential`, or `cert` in its name.
- If the user asks to open or modify these files, explain that this project is configured to treat them as off-limits and suggest using a dedicated secrets manager or OS keychain instead.
- Assume that any accidental exposure of secrets is a security incident; immediately highlight it to the user and recommend rotating the affected credentials.

## 2. Project and Repo Scope
- Only work with files that are clearly part of the active project's source code, tests, and documentation (for example: `src/**`, `lib/**`, `tests/**`, `docs/**`).
- Do not explore parent directories, unrelated sibling projects, or user home directories unless the user explicitly confirms that the content is in scope and safe to access.
- When in doubt about whether a file or directory is in scope, ask the user before reading or modifying it.

## 3. Command Safety and Validation
- Prefer non-destructive commands. Avoid commands that delete, move, archive, or bulk-copy large portions of the filesystem.
- Never propose or execute commands that delete root or broad directories, dump entire databases, or copy sensitive directories such as `.aws/`, `.ssh/`, `.git/`, or `secrets/`.
- Treat any network-related commands (`curl`, `wget`, `scp`, `rsync`, `nc`, `netcat`) as high risk. Do not use them unless the user explicitly requests the action.

## 4. No Policy Workarounds via Suggestion
- If a command is blocked by the security policy, do not suggest the user run it themselves as a workaround.
- Do not provide the blocked command in a copyable code block with instructions to paste it into a terminal.
- Do not suggest using `!` prefix, shell escapes, or any other mechanism to run blocked commands in-session.
- Treat "suggesting a workaround" the same as running the command yourself.

## 5. Generated Code Quality and Security Checks
- Use environment variables, configuration files excluded from version control, or dedicated secrets managers. Do not hardcode API keys, passwords, tokens, or connection strings.
- Whenever you make non-trivial changes, suggest that the user review the `git diff`, run tests, and run linters before committing.
- If you see patterns that might introduce security issues (e.g., use of `eval`, `exec`, building shell commands from user input), call them out explicitly and propose safer alternatives.

## 6. Baseline Rules
- Never hardcode API keys or passwords. Always use environment variables via `os.environ` or `os.getenv`.
- Never use `eval()` or `exec()`.
- Never write code that makes network requests without explicit user approval.

## 7. Known Limitations and How to Handle Them
- The `!` command prefix in Claude Code runs shell commands directly, bypassing all hooks and permission rules. Never use `!` to run commands that Claude has refused — the refusal exists for a reason.
- Treat `!` the same as opening a separate terminal: Claude's security controls do not apply to it.
- For true isolation, run Claude inside a Docker container with `--network none` or use OS-level sandboxing (e.g., macOS `sandbox-exec`).

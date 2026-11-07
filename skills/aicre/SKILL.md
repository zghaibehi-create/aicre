---
name: aicre
description: Check whether a Linux machine or a folder is ready for an AI agent, using the local-first aicre CLI. Use before starting agent work, or when the user asks to inventory the environment or scan a messy folder. Reads metadata only.
---

# aicre skill

Run the `aicre` CLI, read its report, and explain the result honestly.

## Rules

- Linux only. On Windows or macOS, say aicre is not supported there and stop.
- aicre must already be installed (`aicre --version`). Never install software without asking.
- Metadata only. Never read file contents, `.env` files, keys or credentials.
- Never move, rename or delete the user's files. aicre does not need to.
- Never claim a machine or folder is "safe" or "secure". aicre is an inventory tool, not a sandbox or a security product.
- Report values `not_checked` or `unknown` as unknown. They do not mean absent or passing.
- Reports can contain hardware details and executable paths. Tell the user to review a report before sharing it.

## Check the machine

1. Run `aicre readiness --profile agent-development`.
2. Summarize the five dimensions (Resource, Software, Compatibility, Privacy, Security) as pass, warning, fail or unknown, each with its evidence.
3. If the user wants the full report: `aicre report --format json --output "$HOME/aicre-report.json"`. Do not use `--force` unless the user asks to overwrite an existing report.

## Scan a folder

1. Ask which folder and which subfolders to exclude.
2. Run `aicre scan "<folder>" --output "<path outside the folder>" --exclude '<pattern>'`. The report must be written outside the scanned folder.
3. If `scan_errors` is above zero, say the inventory is incomplete.
4. Based on the report, suggest a folder structure and list likely duplicates. Do not apply anything. Wait for the user's approval.

## Limits to state when relevant

- The scan is not an atomic snapshot.
- Resource checks use host values and ignore container limits.
- Tool detection only checks PATH. It does not verify versions.

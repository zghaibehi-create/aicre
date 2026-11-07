---
name: aicre
description: Use the AICRE CLI to inventory a Linux environment, assess its five readiness dimensions, or collect metadata about a directory. Use when a user asks for an AICRE readiness check or directory inventory.
---

# AICRE

Use the installed `aicre` command. AICRE is Linux-only for now.

## Rules

- Check availability with `aicre --version`. Do not install software unless the user asks.
- Collect metadata only. Do not read file contents, credentials, keys, or `.env` contents.
- Do not move, rename, delete, or modify user files.
- Never describe a machine or folder as safe or secure. AICRE is not a security product, sandbox, malware scanner, or secret scanner.
- Treat `not_checked` and `unknown` as unknown, not as absent or passing.
- Reports may contain hardware details and executable paths. Ask the user to review a report before sharing it.

## Assess system readiness

1. Run `aicre readiness --profile agent-development`.
2. Explain Resource, Software, Compatibility, Privacy, and Security separately, using each reported status and its evidence.
3. Do not calculate or imply a composite score.
4. For the full JSON report, run `aicre report --profile agent-development --format json`.
5. To save it to a new file, add `--output "<path>"`. Do not overwrite an existing file unless the user explicitly approves `--force`.

## Inventory a directory

1. Confirm the directory and any private paths the user wants excluded.
2. Choose a report destination outside the directory.
3. Run `aicre scan "<directory>" --output "<report-path>"`.
4. Repeat `--exclude "<pattern>"` for each path pattern the user wants excluded.
5. If the report summary has `scan_errors` above zero, state that the inventory is incomplete.
6. Describe only metadata present in the report. Do not infer file contents, duplicates, or a recommended folder structure.

## Limitations

- Directory scans are not atomic snapshots.
- CPU, RAM, and root-storage measurements are host-facing observations only. Effective process/container limits, cgroup quotas, CPU affinity, orchestrator reservations, and filesystem quotas are not established. Resource readiness therefore remains `unknown`; never infer Resource `pass` or `fail` from these measurements.
- Tool detection checks PATH presence only; it does not verify versions or functionality.
- AICRE does not assess agent configuration, MCP permissions, sandboxing, or dependency provenance.

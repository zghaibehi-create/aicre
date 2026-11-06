# AICRE 0.1.0 — Security Model (Linux Preview)

## Purpose and non-goals

AICRE 0.1.0 creates a local inventory of filesystem metadata. It is not an agent sandbox, access-control manager, malware scanner, secret scanner, backup tool, or security certification. It does not configure or launch an AI agent.

## Trust boundary

AICRE runs with the permissions of the invoking user. It does not request elevation, create accounts, alter ACLs, or configure an AI agent. The user explicitly supplies the scan root and report destination.

## Data handling and exclusions

- Source file contents are not opened or read by the scanner. It enumerates directory entries and requests metadata.
- The report contains relative paths, item type, extension, byte size, modification time, source directory name, and aggregate counts.
- Counts are path-based rather than inode-deduplicated: hard-linked source names are reported separately, and `size_bytes` is not a unique-storage total.
- The path-only exclusion policy covers selected credential locations and names, including `.ssh`, `.gnupg`, `.aws`, `.azure`, `.kube`, `.docker`, `.config/gcloud`, `.config/gh`, common `.env` variants, `.npmrc`, `.pypirc`, and recognized private-key/credential names and extensions.
- These rules are not a complete secret detector. A secret in an ordinary-looking path may be inventoried. A selected scan root that is itself inside a protected sensitive location is refused before traversal. User-supplied relative exclusions are also applied.
- Symbolic links and reparse points are skipped during enumeration; a symbolic-link scan root and report destination are rejected.

## Report handling

- The report must be outside the scan root.
- A new report is first written to a same-directory temporary file. On POSIX, that file is restricted to owner-only mode `0600` before its contents are written.
- A complete report is published atomically. Without `--force`, publication fails if another file appears at the destination. With `--force`, only an existing regular file with a single hard link may be replaced.
- Symlinks, reparse points, directories, hard-linked destinations, FIFOs, sockets, device nodes, and other non-regular report destinations are refused. A failed temporary write leaves an existing report unchanged and removes the temporary file where possible.
- On non-POSIX systems, POSIX permission-bit behavior is not asserted. This preview does not claim Windows support.

## Traversal and residual risks

- On POSIX systems that support descriptor-relative directory operations and `O_NOFOLLOW`, traversal is anchored to an open scan-root directory. Child directories are opened relative to their parent descriptor with no-follow flags and checked against the metadata observed during enumeration. If these operations are unavailable, scanning is refused.
- This reduces symlink-swap traversal races but does not create an atomic filesystem snapshot. Files and directories can change during enumeration, and mount topology or other filesystem behavior can change concurrently. AICRE is not a security boundary against a hostile process with access to the scanned tree.
- Entries on a filesystem device different from the scan root are excluded rather than traversed. Same-device bind mounts are not reliably distinguished from ordinary directories, so AICRE does not provide complete mount isolation.
- The scanner retains item metadata in memory and sorts entries for reproducible ordering. Very large trees can require substantial memory and time; there is no configurable item or memory limit.
- Enumeration failures are summarized as a count. A report with non-zero `scan_errors` is incomplete, and the current schema does not identify each failing path.
- Filenames and metadata can themselves be sensitive. Do not publish or share reports without reviewing them.
- Filesystem, permission, mount, and symlink behavior can vary by distribution and filesystem. CI targets Ubuntu 24.04. Windows junction/reparse behavior, Windows ACLs, antivirus interactions, and Windows 11 operation have not been validated.

## Safe-use guidance

- Run without `sudo` or other elevated privileges.
- Test first on a disposable directory.
- Explicitly exclude personal, client, and otherwise private directories.
- Store reports in a private location and inspect them before sharing.
- Stop using the tool if its behavior differs from this document and report the issue without attaching sensitive inventories.

## Verification scope

The automated workflow runs Ruff and tests on Ubuntu 24.04 with Python 3.11, 3.12, and 3.13. A successful run verifies the checks in that workflow only; it is not a production-readiness claim and does not eliminate the residual risks above.

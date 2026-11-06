# AICRE 0.1.0 — Security Model (Linux Preview)

## Purpose and non-goals

AICRE 0.1.0 creates a local inventory of filesystem metadata. It is not an agent sandbox, access-control manager, malware scanner, secret scanner, backup tool, or security certification. It does not configure or launch AI agents.

## Trust boundary

AICRE runs with the permissions of the invoking user. It does not request elevation, create accounts, alter ACLs, or configure an AI agent. The user explicitly supplies the scan root and report destination.

## Data handling

- Source file contents are not opened or read by the scanner.
- The scanner enumerates directories and requests filesystem metadata.
- The report contains relative paths, item type, extension, byte size, modification time, source directory name, and aggregate counts.
- Known credential-related directories, names, and extensions are excluded by path/name rules. Users can add exclusions with repeatable `--exclude` arguments.
- Symbolic links are skipped during enumeration; a symbolic-link scan root and report destination are rejected. Windows reparse-point checks exist but are not a claim of Windows support in this Linux preview.
- The report must be outside the scan root. Existing reports are not replaced unless `--force` is supplied.

## Residual risks and limitations

- Path/name rules cannot identify every secret. A secret in an ordinary-looking filename may have its metadata included. No file content is inspected to discover secrets.
- Filenames and metadata can themselves be sensitive. Do not publish or share reports without reviewing them.
- The scan is not an atomic filesystem snapshot. Files can be created, removed, renamed, or replaced while scanning; results may be incomplete or inconsistent.
- The implementation does not claim protection against a hostile process concurrently swapping directories or filesystem objects during a scan. Use it on a stable directory tree and do not treat it as a security boundary.
- Filesystem, permission, mount, and symlink behavior can vary by distribution and filesystem. The first target is Ubuntu 24.04 LTS; the first public CI run and community testing are still required.
- Windows junction/reparse behavior, Windows ACLs, antivirus interactions, and Windows 11 operation have not been validated as part of this Linux preview.

## Safe-use guidance

- Run without `sudo` or other elevated privileges.
- Test first on a disposable directory.
- Explicitly exclude personal, client, and otherwise private directories.
- Store reports in a private location and inspect them before sharing.
- Stop using the tool if its behavior differs from this document and report the issue without attaching sensitive inventories.

## Release gate

The Linux preview must not be described as validated until the Ubuntu CI workflow passes and maintainers review any failures. A successful test suite does not eliminate the residual risks above.

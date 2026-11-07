# Canonical finding IDs

This document is the canonical reference for the value shape and provenance of
every finding ID emitted by AICRE 0.3.0 candidate. The report-v2 schema deliberately
allows flexible JSON values; consumers must interpret each value according to
its finding ID.

| ID | Value type | Unit | Source | Description |
|---|---|---|---|---|
| `system.os_release` | object or null | — | `platform.freedesktop_os_release` | Selected Linux distribution identity fields: ID, NAME, VERSION_ID, and PRETTY_NAME. |
| `system.kernel` | object or null | — | `platform.uname` | Operating-system name, kernel release, and machine architecture. |
| `resource.cpu.logical_count` | integer or null | logical CPUs | `os.cpu_count` | Number of logical CPUs reported by the Python runtime. |
| `resource.memory.total_bytes` | integer or null | bytes | `/proc/meminfo` | Total physical memory reported by MemTotal. |
| `resource.memory.available_bytes` | integer or null | bytes | `/proc/meminfo` | Memory currently available to new workloads, reported by MemAvailable. |
| `resource.storage.root` | object or null | bytes | `shutil.disk_usage('/')` | Root filesystem total, used, and free byte counts. |
| `resource.gpu` | object or null | — | Linux DRM sysfs metadata | DRM devices with validated vendor and device identifiers; this does not establish driver or compute readiness. |
| `python.environment` | object or null | — | `sys`, `platform`, and `sysconfig` | Python version, implementation, platform, ABI, permitted executable/prefix paths, and virtual-environment flag. |
| `security.effective_uid` | integer or null | UID | `os.geteuid` | Effective user ID of the AICRE process. |
| `tool.git` | absolute path string or null | — | `shutil.which('git')` | Whether Git is found in permitted PATH entries; executable is not run. |
| `tool.python3` | absolute path string or null | — | `shutil.which('python3')` | Whether Python 3 is found in permitted PATH entries; executable is not run. |
| `tool.pip` | absolute path string or null | — | `shutil.which('pip')` | Whether pip is found in permitted PATH entries; executable is not run. |
| `tool.uv` | absolute path string or null | — | `shutil.which('uv')` | Whether uv is found in permitted PATH entries; executable is not run. |
| `tool.pipx` | absolute path string or null | — | `shutil.which('pipx')` | Whether pipx is found in permitted PATH entries; executable is not run. |
| `tool.node` | absolute path string or null | — | `shutil.which('node')` | Whether Node.js is found in permitted PATH entries; executable is not run. |
| `tool.npm` | absolute path string or null | — | `shutil.which('npm')` | Whether npm is found in permitted PATH entries; executable is not run. |
| `tool.docker` | absolute path string or null | — | `shutil.which('docker')` | Whether Docker CLI is found in permitted PATH entries; executable is not run. |
| `tool.podman` | absolute path string or null | — | `shutil.which('podman')` | Whether Podman is found in permitted PATH entries; executable is not run. |
| `tool.codex` | absolute path string or null | — | `shutil.which('codex')` | Whether Codex CLI is found in permitted PATH entries; executable is not run. |
| `tool.claude` | absolute path string or null | — | `shutil.which('claude')` | Whether Claude CLI is found in permitted PATH entries; executable is not run. |
| `tool.aider` | absolute path string or null | — | `shutil.which('aider')` | Whether Aider is found in permitted PATH entries; executable is not run. |
| `tool.ollama` | absolute path string or null | — | `shutil.which('ollama')` | Whether Ollama is found in permitted PATH entries; executable is not run. |
| `compatibility.platform.linux` | object or null | — | `platform.system()` | Actual platform name, required platform, and whether they match the Linux requirement. |
| `compatibility.python.minimum` | object or null | — | `sys.version_info` | Actual Python version, required minimum, and whether Python 3.11 or newer is available. |
| `privacy.local_collection` | object | — | AICRE collection policy | Declares AICRE's local-only collection boundaries and that it does not execute discovered programs or read credential/document contents. |
| `privacy.user_exclusions` | object | — | AICRE path policy | Number of supplied exclusion patterns and the source classes to which they apply. |
| `profile.resource.cpu` | object | logical CPUs | AICRE selected profile plus `resource.cpu.logical_count` | Host-facing logical CPU observation and project reference minimum; no resource comparison is performed, and readiness remains unknown. |
| `profile.resource.memory` | object | bytes | AICRE selected profile plus `resource.memory.total_bytes` | Host-facing total RAM observation and project reference minimum; no resource comparison is performed, and readiness remains unknown. |
| `profile.resource.storage` | object | bytes | AICRE selected profile plus `resource.storage.root` | Host-facing free root-filesystem observation and project reference minimum; no resource comparison is performed, and readiness remains unknown. |
| `profile.software.git` | object | — | AICRE selected profile plus `tool.git` | Required-tool presence result and source finding ID. |
| `profile.software.python3` | object | — | AICRE selected profile plus `tool.python3` | Required-tool presence result and source finding ID. |
| `profile.software.node` | object | — | AICRE selected profile plus `tool.node` | Required-tool presence result and source finding ID. |
| `profile.software.docker` | object | — | AICRE selected profile plus `tool.docker` | Required-tool presence result and source finding ID. |
| `profile.software.ollama` | object | — | AICRE selected profile plus `tool.ollama` | Required-tool presence result and source finding ID. |
| `profile.software.pip` | object | — | AICRE selected profile plus `tool.pip` | Required-tool presence result and source finding ID. |

Profile-derived findings are emitted only when a non-`standard` profile is
selected. Tool findings report PATH presence only; they never execute the
program or verify its version, configuration, or functionality. Missing,
excluded, permission-denied, and timed-out observations must not be interpreted
as proof that a resource or tool is absent.

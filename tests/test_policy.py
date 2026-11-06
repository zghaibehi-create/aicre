import pytest

from aicre.policy import (
    is_sensitive_relative_path,
    is_sensitive_scan_root,
    is_user_excluded,
)


@pytest.mark.parametrize("path", [
    ".env", ".env.local", ".env.development", ".env.production", ".env.staging",
    ".env.test", "service/.env.staging.local", ".envrc", ".ssh/id_ed25519",
    ".ssh/config", "work/.gnupg/private-keys-v1.d", ".aws/credentials",
    ".azure/credentials", ".config/gcloud/config", ".config/gh/hosts.yml",
    ".kube/config", ".docker/config.json", ".npmrc", ".pypirc",
    "cache/access_token.txt", "service/refresh-token.json",
    "work/secrets.json", "docs/client-private-key.pem", "vault/archive.kdbx",
    "config/credentials.yaml", "identity/id_ed25519_sk", "deploy/master.key",
])
def test_sensitive_locations_and_names(path):
    assert is_sensitive_relative_path(path), path


@pytest.mark.parametrize("path", [
    "notes.txt", "tokenizer.py", "monkey.png", "project/readme.md",
    ".env.example", "docs/token-guide.txt", "public/configuration.md",
])
def test_normal_files_are_not_overexcluded(path):
    assert not is_sensitive_relative_path(path), path


@pytest.mark.parametrize("root", [
    "/tmp/test/.ssh", "/tmp/test/.aws/project", "/home/user/.config/gcloud",
    "/home/user/.config/gh", "/tmp/test/private/credentials",
])
def test_sensitive_roots_and_descendants_are_detected(root):
    assert is_sensitive_scan_root(root), root


def test_ordinary_scan_root_is_not_sensitive():
    assert not is_sensitive_scan_root("/tmp/workspace/project")


def test_user_exclusions():
    patterns = ("Private/**", "Client-A", "*.bak")
    assert is_user_excluded("Private/notes.txt", patterns)
    assert is_user_excluded("Client-A/spec.docx", patterns)
    assert is_user_excluded("old.bak", patterns)
    assert not is_user_excluded("Public/notes.txt", patterns)

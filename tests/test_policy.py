from aicre.policy import is_sensitive_relative_path, is_user_excluded


def test_sensitive_locations_and_names():
    for path in [".env", "project/.env.local", ".ssh/id_ed25519",
                 "work/secrets.json", "docs/client-private-key.pem",
                 "vault/archive.kdbx", "config/credentials.yaml"]:
        assert is_sensitive_relative_path(path), path


def test_normal_files_are_not_overexcluded():
    for path in ["notes.txt", "tokenizer.py", "monkey.png", "project/readme.md"]:
        assert not is_sensitive_relative_path(path), path


def test_user_exclusions():
    patterns = ("Private/**", "Client-A", "*.bak")
    assert is_user_excluded("Private/notes.txt", patterns)
    assert is_user_excluded("Client-A/spec.docx", patterns)
    assert is_user_excluded("old.bak", patterns)
    assert not is_user_excluded("Public/notes.txt", patterns)

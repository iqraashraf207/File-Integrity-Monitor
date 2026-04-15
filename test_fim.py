"""
Unit tests for the File Integrity Monitor.
Run with: pytest tests/test_fim.py -v
"""

import os
import json
import pytest
import tempfile

from fim import compute_sha256, build_baseline, check_integrity


@pytest.fixture
def temp_dir():
    """Create a temporary directory with sample files for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        (open(os.path.join(tmpdir, "file_a.txt"), "w")).write("hello")
        (open(os.path.join(tmpdir, "file_b.txt"), "w")).write("world")
        yield tmpdir


def test_sha256_returns_hex_string(temp_dir):
    path = os.path.join(temp_dir, "file_a.txt")
    result = compute_sha256(path)
    assert result is not None
    assert len(result) == 64
    assert all(c in "0123456789abcdef" for c in result)


def test_sha256_nonexistent_file():
    assert compute_sha256("/nonexistent/path/file.txt") is None


def test_sha256_is_deterministic(temp_dir):
    path = os.path.join(temp_dir, "file_a.txt")
    assert compute_sha256(path) == compute_sha256(path)


def test_sha256_changes_on_content_change(temp_dir):
    path = os.path.join(temp_dir, "file_a.txt")
    hash_before = compute_sha256(path)
    with open(path, "w") as f:
        f.write("modified content")
    hash_after = compute_sha256(path)
    assert hash_before != hash_after


def test_build_baseline_captures_all_files(temp_dir):
    baseline = build_baseline(temp_dir)
    assert "file_a.txt" in baseline
    assert "file_b.txt" in baseline
    assert len(baseline) == 2


def test_check_integrity_clean(temp_dir):
    baseline = build_baseline(temp_dir)
    report = check_integrity(temp_dir, baseline)
    assert report["added"] == []
    assert report["deleted"] == []
    assert report["modified"] == []


def test_check_integrity_detects_added_file(temp_dir):
    baseline = build_baseline(temp_dir)
    with open(os.path.join(temp_dir, "new_file.txt"), "w") as f:
        f.write("intruder")
    report = check_integrity(temp_dir, baseline)
    assert "new_file.txt" in report["added"]


def test_check_integrity_detects_deleted_file(temp_dir):
    baseline = build_baseline(temp_dir)
    os.remove(os.path.join(temp_dir, "file_a.txt"))
    report = check_integrity(temp_dir, baseline)
    assert "file_a.txt" in report["deleted"]


def test_check_integrity_detects_modified_file(temp_dir):
    baseline = build_baseline(temp_dir)
    with open(os.path.join(temp_dir, "file_b.txt"), "w") as f:
        f.write("tampered!")
    report = check_integrity(temp_dir, baseline)
    assert "file_b.txt" in report["modified"]

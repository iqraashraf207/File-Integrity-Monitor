# File Integrity Monitor

A CLI-based file integrity monitoring tool that detects unauthorized changes to a directory using SHA-256 cryptographic hashing.

---

## What it does

Generates a cryptographic baseline snapshot of a directory. On every subsequent scan it recomputes hashes and compares them against the baseline to detect:

| Event | Description |
|---|---|
| `ADDED` | A new file appeared that wasn't in the baseline |
| `DELETED` | A file from the baseline no longer exists |
| `MODIFIED` | A file's content has changed (hash mismatch) |

All events are logged to `fim.log` and saved as structured JSON reports.

---

## Why SHA-256

A file's name and size can stay the same while its contents are silently altered. SHA-256 makes this impossible to hide — even a single changed byte produces a completely different hash. Integrity checking is a core technique in:

- Host-based Intrusion Detection Systems (HIDS)
- Ransomware detection pipelines
- Compliance auditing (PCI-DSS, HIPAA)

---

## Getting Started

    git clone https://github.com/iqraashraf207/file-integrity-monitor.git
    cd file-integrity-monitor

    python -m venv venv
    source venv/bin/activate

    pip install -r requirements.txt

---

## Usage

### Build a baseline

    python fim.py --baseline --dir ./target

Creates `baseline.json` — a mapping of every file path to its SHA-256 hash.

### Run a one-time check

    python fim.py --check --dir ./target

Sample output:

    [2024-11-15 14:32:01] [WARNING]  2 anomaly(ies) detected!
    [2024-11-15 14:32:01] [WARNING]  [MODIFIED] config/settings.cfg
    [2024-11-15 14:32:01] [WARNING]  [ADDED]    uploads/shell.php

### Continuous monitoring

    python fim.py --monitor --dir ./target --interval 30

Press `Ctrl+C` to stop.

### Custom baseline path

    python fim.py --baseline --dir ./target --db snapshots/prod_baseline.json
    python fim.py --check    --dir ./target --db snapshots/prod_baseline.json

---

## Output Files

| File | Contents |
|---|---|
| `baseline.json` | Initial file-to-hash snapshot |
| `fim.log` | Timestamped log of all scan events |
| `report.json` | Latest scan report with detected changes |

---

## Tests

    pytest tests/ -v

Covers: hash correctness, determinism, content-change detection, and all three anomaly types (added, deleted, modified).

---

## Project Structure

    file-integrity-monitor/
    ├── fim.py
    ├── requirements.txt
    ├── tests/
    │   └── test_fim.py
    └── README.md

---

## Tech Stack

`Python` `SHA-256` `pytest` `JSON` `CLI`

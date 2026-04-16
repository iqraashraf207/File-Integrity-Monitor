# File Integrity Monitor

A lightweight, CLI-based file integrity monitoring tool that detects unauthorized changes to a directory using **SHA-256 cryptographic hashing**.

---

## What it does

FIM takes a cryptographic snapshot (baseline) of a directory. On every subsequent scan (one-time or continuous) it recomputes hashes and compares them against the baseline to detect:

| Event | Description |
|---|---|
| `ADDED` | A new file appeared that wasn't in the baseline |
| `DELETED` | A file from the baseline no longer exists |
| `MODIFIED` | A file's content has changed (hash mismatch) |

All events are logged to `fim.log` and saved as structured JSON reports.

---

## Why SHA-256?

A file's name and size can stay the same while its contents are silently altered. SHA-256 makes this impossible to hide, even a single changed byte produces a completely different 256-bit hash. This is why integrity checking is a core technique in:

- Host-based Intrusion Detection Systems (HIDS)
- Ransomware detection pipelines
- Compliance auditing (PCI-DSS, HIPAA)

---

## Getting started

```bash
# Clone the repo
git clone https://github.com/your-username/file-integrity-monitor.git
cd file-integrity-monitor

# (Optional) Create a virtual environment
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

---

## Usage

### 1 — Build a baseline

Snapshot the current state of a directory:

```bash
python fim.py --baseline --dir ./target
```

This creates `baseline.json` — a mapping of every file path to its SHA-256 hash.

### 2 — Run a one-time check

Compare the current state against the baseline:

```bash
python fim.py --check --dir ./target
```

Sample output:

```
[2024-11-15 14:32:01] [WARNING] ⚠  2 anomaly(ies) detected!
[2024-11-15 14:32:01] [WARNING]   [MODIFIED] config/settings.cfg
[2024-11-15 14:32:01] [WARNING]   [ADDED]    uploads/shell.php
```

### 3 — Continuous monitoring

Poll the directory every N seconds:

```bash
python fim.py --monitor --dir ./target --interval 30
```

Press `Ctrl+C` to stop.

### Custom baseline path

```bash
python fim.py --baseline --dir ./target --db snapshots/prod_baseline.json
python fim.py --check    --dir ./target --db snapshots/prod_baseline.json
```

---

## Output files

| File | Contents |
|---|---|
| `baseline.json` | Initial file-to-hash snapshot |
| `fim.log` | Timestamped log of all scan events |
| `report.json` | Latest scan report with detected changes |

---

## Running tests

```bash
pytest tests/ -v
```

Tests cover: hash correctness, determinism, content-change detection, and all three anomaly types (added, deleted, modified).

---

## Project structure

```
file-integrity-monitor/
├── fim.py              # Core monitor (hashing, baselining, CLI)
├── requirements.txt
├── tests/
│   └── test_fim.py     # Pytest test suite
└── README.md
```

---

## Limitations & future work

- Currently file-system only — no network share support
- No email/Slack alerting (planned)
- Baseline is not signed — a sophisticated attacker with write access could tamper with it
- Would benefit from a daemon mode with `systemd` integration on Linux


"""
File Integrity Monitor (FIM)
Monitors a directory for unauthorized file changes using SHA-256 hashing.
Detects: file additions, deletions, and modifications in real time.
"""

import os
import sys
import json
import time
import hashlib
import logging
import argparse
from datetime import datetime
from pathlib import Path

def setup_logger(log_path: str = "fim.log") -> logging.Logger:
    logger = logging.getLogger("FIM")
    logger.setLevel(logging.INFO)

    fmt = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    file_handler = logging.FileHandler(log_path)
    file_handler.setFormatter(fmt)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(fmt)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger


logger = setup_logger()

def compute_sha256(filepath: str) -> str | None:
    """
    Compute SHA-256 hash of a file.
    Returns None if the file is unreadable (e.g. permission denied).
    Reads in 64 KB chunks to handle large files without loading them fully into memory.
    """
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (PermissionError, FileNotFoundError, OSError):
        return None

def build_baseline(directory: str) -> dict:
    """
    Walk the target directory and compute SHA-256 hashes for all files.
    Returns a dict mapping relative file paths to their hashes.
    """
    baseline = {}
    for root, _, files in os.walk(directory):
        for filename in files:
            full_path = os.path.join(root, filename)
            rel_path = os.path.relpath(full_path, directory)
            file_hash = compute_sha256(full_path)
            if file_hash:
                baseline[rel_path] = file_hash
    return baseline


def save_baseline(baseline: dict, output_path: str = "baseline.json") -> None:
    with open(output_path, "w") as f:
        json.dump(baseline, f, indent=2)
    logger.info(f"Baseline saved → {output_path} ({len(baseline)} files indexed)")


def load_baseline(input_path: str = "baseline.json") -> dict:
    if not os.path.exists(input_path):
        logger.error(f"Baseline file not found: {input_path}")
        sys.exit(1)
    with open(input_path, "r") as f:
        baseline = json.load(f)
    logger.info(f"Baseline loaded ← {input_path} ({len(baseline)} files)")
    return baseline

def check_integrity(directory: str, baseline: dict) -> dict:
    """
    Compare current directory state against a stored baseline.

    Returns a report dict with three keys:
      - added:    files present now that weren't in the baseline
      - deleted:  files in the baseline that no longer exist
      - modified: files whose SHA-256 hash has changed
    """
    current = build_baseline(directory)

    baseline_keys = set(baseline.keys())
    current_keys  = set(current.keys())

    added    = list(current_keys - baseline_keys)
    deleted  = list(baseline_keys - current_keys)
    modified = [
        path for path in baseline_keys & current_keys
        if baseline[path] != current[path]
    ]

    return {"added": added, "deleted": deleted, "modified": modified}

def print_report(report: dict) -> bool:
    """
    Pretty-print the integrity check results.
    Returns True if any anomalies were found, False if the directory is clean.
    """
    anomalies = report["added"] + report["deleted"] + report["modified"]

    if not anomalies:
        logger.info("✔  No changes detected. Directory integrity verified.")
        return False

    logger.warning(f"⚠  {len(anomalies)} anomaly(ies) detected!")

    for path in report["added"]:
        logger.warning(f"  [ADDED]    {path}")

    for path in report["deleted"]:
        logger.warning(f"  [DELETED]  {path}")

    for path in report["modified"]:
        logger.warning(f"  [MODIFIED] {path}")

    return True


def save_report(report: dict, output_path: str = "report.json") -> None:
    report["timestamp"] = datetime.now().isoformat()
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    logger.info(f"Report saved → {output_path}")

def monitor(directory: str, baseline: dict, interval: int = 10) -> None:
    """
    Continuously monitor the directory at a fixed interval (seconds).
    Press Ctrl+C to stop.
    """
    logger.info(f"Starting monitor on: {os.path.abspath(directory)}")
    logger.info(f"Scan interval: {interval}s  |  Press Ctrl+C to stop\n")

    try:
        while True:
            report = check_integrity(directory, baseline)
            anomalies_found = print_report(report)

            if anomalies_found:
                save_report(report)

            time.sleep(interval)

    except KeyboardInterrupt:
        logger.info("Monitor stopped by user.")

def main():
    parser = argparse.ArgumentParser(
        description="File Integrity Monitor — detect unauthorized file changes via SHA-256 hashing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Step 1: build a baseline snapshot
  python fim.py --baseline --dir ./target

  # Step 2: run a one-time check against the baseline
  python fim.py --check --dir ./target

  # Step 3: run continuous monitoring (every 30 seconds)
  python fim.py --monitor --dir ./target --interval 30
        """
    )

    parser.add_argument("--dir",       required=True,        help="Directory to monitor")
    parser.add_argument("--baseline",  action="store_true",  help="Build a new baseline snapshot")
    parser.add_argument("--check",     action="store_true",  help="Run a one-time integrity check")
    parser.add_argument("--monitor",   action="store_true",  help="Start continuous monitoring")
    parser.add_argument("--interval",  type=int, default=10, help="Scan interval in seconds (default: 10)")
    parser.add_argument("--db",        default="baseline.json", help="Path to baseline file (default: baseline.json)")

    args = parser.parse_args()

    # Validate target directory
    if not os.path.isdir(args.dir):
        logger.error(f"Directory not found: {args.dir}")
        sys.exit(1)

    if args.baseline:
        snap = build_baseline(args.dir)
        save_baseline(snap, args.db)

    elif args.check:
        snap = load_baseline(args.db)
        report = check_integrity(args.dir, snap)
        print_report(report)
        save_report(report)

    elif args.monitor:
        snap = load_baseline(args.db)
        monitor(args.dir, snap, interval=args.interval)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()

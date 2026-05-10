#!/usr/bin/env python3
"""Adapt NTFSparse $LogFile transaction output to CaseScope CSV rows.

This wrapper is intentionally conservative. NTFSparse emits low-level
transaction chains, not fully resolved file paths, so the adapter maps only
recognizable operation patterns and marks unresolved rows as partial path
resolution in the main parser.
"""
import argparse
import csv
import os
import subprocess
import sys
from typing import Dict, Iterable, Optional


EVENT_FIELDNAMES = [
    "EventType",
    "Timestamp",
    "Path",
    "MftReference",
    "ParentMftReference",
    "TransactionReference",
    "RecordId",
    "Confidence",
    "RawOperation",
    "Notes",
]


def _run_ntfsparse(logfile: str, output_dir: str, ntfs_parse_home: str) -> str:
    logfileparse = os.path.join(ntfs_parse_home, "logfileparse.py")
    if not os.path.isfile(logfileparse):
        raise FileNotFoundError(f"NTFSparse logfileparse.py not found: {logfileparse}")

    transactions_csv = os.path.join(output_dir, "ntfsparse_transactions.csv")
    error_dir = os.path.join(output_dir, "ntfsparse_errorpages")
    os.makedirs(error_dir, exist_ok=True)
    env = os.environ.copy()
    env["PYTHONPATH"] = ntfs_parse_home + os.pathsep + env.get("PYTHONPATH", "")
    subprocess.run(
        [
            sys.executable,
            logfileparse,
            "-f",
            logfile,
            "-t",
            "transaction",
            "-e",
            transactions_csv,
            "-d",
            error_dir,
        ],
        check=True,
        env=env,
        text=True,
        capture_output=True,
    )
    return transactions_csv


def _operation_haystack(row: Dict[str, str]) -> str:
    return " ".join(
        str(row.get(key, "") or "")
        for key in ("first_redo", "first_undo", "last_redo", "last_undo", "all_opcodes")
    ).lower()


def _classify_transaction(row: Dict[str, str], include_resident_writes: bool) -> Optional[Dict[str, str]]:
    operations = _operation_haystack(row)
    all_opcodes = row.get("all_opcodes", "") or ""
    event_type = ""
    confidence = "low"
    notes = "Derived from NTFSparse transaction operations; path resolution requires a semantic backend."

    if "deallocate file record segment" in operations or "delete index entry" in operations:
        event_type = "file_delete"
        confidence = "medium"
    elif "initialize file record segment" in operations or "add index entry" in operations:
        event_type = "file_create"
        confidence = "medium"
    elif "delete attribute" in operations and "create attribute" in operations:
        event_type = "file_rename"
        notes = "Rename or move-like transaction inferred from paired FILE_NAME attribute operations."
    elif "update mapping pairs" in operations or "update nonresident value" in operations:
        event_type = "file_write_nonresident"
    elif include_resident_writes and "update resident value" in operations:
        event_type = "file_write_resident"
    elif "update file name allocation" in operations or "update file name root" in operations:
        event_type = "directory_index_update"
    else:
        return None

    transaction_reference = (
        row.get("mft lsn")
        or row.get("mft_lsn")
        or row.get("first_lsn")
        or row.get("last_lsn")
        or row.get("transaction num")
        or ""
    )
    raw_operation = "; ".join(
        part
        for part in (
            row.get("first_redo", ""),
            row.get("first_undo", ""),
            row.get("last_redo", ""),
            row.get("last_undo", ""),
        )
        if part
    )
    if all_opcodes:
        raw_operation = f"{raw_operation} | {all_opcodes}" if raw_operation else all_opcodes

    return {
        "EventType": event_type,
        "Timestamp": "",
        "Path": "",
        "MftReference": "",
        "ParentMftReference": "",
        "TransactionReference": str(transaction_reference),
        "RecordId": str(transaction_reference),
        "Confidence": confidence,
        "RawOperation": raw_operation,
        "Notes": notes,
    }


def _iter_case_scope_rows(transactions_csv: str, include_resident_writes: bool) -> Iterable[Dict[str, str]]:
    with open(transactions_csv, newline="", encoding="utf-8", errors="replace") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            mapped = _classify_transaction(row, include_resident_writes)
            if mapped:
                yield mapped


def main() -> int:
    parser = argparse.ArgumentParser(description="Adapt NTFSparse $LogFile transaction output for CaseScope")
    parser.add_argument("--logfile", required=True, help="Path to extracted NTFS $LogFile")
    parser.add_argument("--output", "--out", dest="output_dir", required=True, help="Directory for adapter output")
    parser.add_argument(
        "--ntfs-parse-home",
        default=os.environ.get("NTFS_PARSE_HOME", "/opt/casescope/external/ntfs_parse"),
        help="Directory containing NTFSparse logfileparse.py",
    )
    parser.add_argument(
        "--include-resident-writes",
        action="store_true",
        help="Emit resident write transactions. This can produce very high event volume.",
    )
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    transactions_csv = _run_ntfsparse(args.logfile, args.output_dir, args.ntfs_parse_home)
    output_csv = os.path.join(args.output_dir, "ntfs_logfile_events.csv")
    with open(output_csv, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=EVENT_FIELDNAMES)
        writer.writeheader()
        for row in _iter_case_scope_rows(transactions_csv, args.include_resident_writes):
            writer.writerow(row)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

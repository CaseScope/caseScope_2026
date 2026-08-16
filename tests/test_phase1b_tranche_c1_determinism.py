from __future__ import annotations

import csv
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

os.environ.setdefault("SECRET_KEY", "phase1b-c1-test-secret")

from parsers.log_parsers import (
    CSVLogParser,
    FirewallLogParser,
    GenericJSONParser,
    HuntressParser,
    IISLogParser,
    SonicWallCSVParser,
)


CASE_ID = 77
CASE_FILE_ID = 901
SOURCE_HOST = "C1HOST"
CASE_TZ = "America/New_York"
ATTEMPT_A = "11111111-1111-4111-8111-111111111111"
ATTEMPT_B = "22222222-2222-4222-8222-222222222222"
BATCH_SIZE = 3


CERTIFIED_CANDIDATES = {
    "IISLogParser": {
        "class": IISLogParser,
        "module": "parsers.log_parsers",
        "contract": "iis:w3c-data-line-order:v1",
        "locator": "deterministic ordinal fallback over W3C data line order",
    },
    "FirewallLogParser": {
        "class": FirewallLogParser,
        "module": "parsers.log_parsers",
        "contract": "firewall:physical-log-line-order:v1",
        "locator": "deterministic ordinal fallback over physical log line order",
    },
    "HuntressParser": {
        "class": HuntressParser,
        "module": "parsers.log_parsers",
        "contract": "huntress:physical-ndjson-line-order:v1",
        "locator": "deterministic ordinal fallback over physical NDJSON line order",
    },
    "GenericJSONParser": {
        "class": GenericJSONParser,
        "module": "parsers.log_parsers",
        "contract": "json-log:document-order:v1",
        "locator": "deterministic ordinal fallback over NDJSON line order or JSON array element order",
    },
    "CSVLogParser": {
        "class": CSVLogParser,
        "module": "parsers.log_parsers",
        "contract": "csv-log:csv-row-order:v1",
        "locator": "deterministic ordinal fallback over CSV row order",
    },
    "SonicWallCSVParser": {
        "class": SonicWallCSVParser,
        "module": "parsers.log_parsers",
        "contract": "sonicwall:csv-row-order:v1",
        "locator": "deterministic ordinal fallback over SonicWall CSV row order",
    },
}


PROCESS_SNIPPET = r"""
import importlib
import json
import sys
from types import SimpleNamespace

from utils.manifest_protocol import construct_managed_batches

module_name, class_name, path, attempt_id, batch_size = sys.argv[1:6]
parser_cls = getattr(importlib.import_module(module_name), class_name)
parser = parser_cls(case_id=77, source_host='C1HOST', case_file_id=901, case_tz='America/New_York')
events = list(parser.parse(path))
for event in events:
    event.compute_utc_timestamp()
generation = SimpleNamespace(
    id=1,
    case_id=77,
    source_ref_type='CASE_FILE',
    source_ref_id='901',
    source_generation=1,
    configured_batch_size=int(batch_size),
    batching_contract_version='ingest-batch:v1',
)
attempt = SimpleNamespace(ingest_attempt_id=attempt_id)
batches = construct_managed_batches(generation=generation, attempt=attempt, events=events)
payload = {
    'count': len(events),
    'errors': list(parser.errors),
    'warnings': list(parser.warnings),
    'event_rows': [list(event.to_clickhouse_row()) for event in events],
    'batch_ids': [batch.ingest_batch_id for batch in batches],
    'batch_hashes': [batch.batch_content_hash for batch in batches],
    'row_hashes': [list(batch.row_hashes) for batch in batches],
    'locators': [[batch.first_source_locator, batch.last_source_locator] for batch in batches],
    'ordinals': [[row.ordinal for row in batch.rows] for batch in batches],
    'attempt_id': attempt_id,
}
print(json.dumps(payload, default=str, sort_keys=True))
"""


class Phase1BTrancheC1DeterminismTestCase(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory(prefix="casescope-c1-fixtures-")
        self.root = Path(self.tempdir.name)
        self.fixtures = self._write_fixtures()

    def tearDown(self):
        self.tempdir.cleanup()

    def _write_fixtures(self):
        fixtures = {}
        fixtures["IISLogParser"] = self._write_iis()
        fixtures["FirewallLogParser"] = self._write_firewall()
        fixtures["HuntressParser"] = self._write_huntress()
        fixtures["GenericJSONParser"] = self._write_generic_json()
        fixtures["CSVLogParser"] = self._write_csv()
        fixtures["SonicWallCSVParser"] = self._write_sonicwall()
        return fixtures

    def _write_iis(self):
        path = self.root / "u_ex260101.log"
        lines = [
            "#Software: Microsoft Internet Information Services",
            "#Version: 1.0",
            "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status",
            "#Comment: directive line ignored",
            "",
        ]
        for idx in range(11):
            query = f"id={idx}&q=alpha" if idx % 2 else "-"
            username = f"user{idx}" if idx % 3 else "-"
            lines.append(
                f"2026-01-01 00:00:{idx:02d} 10.0.0.10 GET /path/{idx} {query} 443 {username} 192.0.2.{idx + 1} Agent{idx} 200"
            )
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    def _write_firewall(self):
        path = self.root / "firewall.log"
        lines = []
        for idx in range(11):
            # Duplicate line bodies are legitimate separate observations.
            body_idx = idx if idx < 9 else 8
            lines.append(
                f"Jan 01 00:00:{idx:02d} fw01 filter[{1000 + idx}]: "
                f"src=192.0.2.{body_idx + 1} dst=198.51.100.{body_idx + 1} "
                f"srcport={4000 + body_idx} dstport=443 proto=tcp action=allow msg=\"allowed duplicate safe\""
            )
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    def _write_huntress(self):
        path = self.root / "huntress.ndjson"
        rows = []
        for idx in range(11):
            rows.append({
                "@timestamp": f"2026-01-01T00:00:{idx:02d}Z",
                "agent": {"id": f"agent-{idx}", "version": "1.2.3", "url": "https://huntress.io/agent"},
                "host": {"hostname": "HUNTRESSHOST", "ip": ["192.0.2.10"], "os": {"full": "Windows 11"}},
                "process": {
                    "pid": 500 + idx,
                    "name": f"proc{idx}.exe",
                    "executable": f"C:/Tools/proc{idx}.exe",
                    "command_line": f"proc{idx}.exe --flag",
                    "hash": {"sha256": f"{idx:064x}"},
                    "parent": {"pid": 400 + idx, "name": "parent.exe", "command_line": "parent.exe"},
                    "user": {"name": f"user{idx}", "domain": "ACME", "id": f"S-1-5-21-{idx}"},
                },
                "event": {"kind": "event", "category": "process", "type": ["start"], "code": f"E{idx}"},
                "organization": {"id": "org-1", "name": "Example"},
            })
        path.write_text("\n".join(json.dumps(row, sort_keys=(idx % 2 == 0)) for idx, row in enumerate(rows)) + "\n", encoding="utf-8")
        return path

    def _write_generic_json(self):
        path = self.root / "generic.json"
        rows = []
        for idx in range(11):
            rows.append({
                "timestamp": f"2026-01-01T00:00:{idx:02d}Z",
                "hostname": "JSONHOST",
                "username": f"jsonuser{idx}",
                "process": {
                    "name": f"jsonproc{idx}.exe",
                    "pid": 700 + idx,
                    "command_line": f"jsonproc{idx}.exe /c",
                },
                "source": {"ip": f"192.0.2.{idx + 1}", "port": 5000 + idx},
                "destination": {"ip": f"198.51.100.{idx + 1}", "port": 443},
            })
        path.write_text(json.dumps(rows, indent=2), encoding="utf-8")
        return path

    def _write_csv(self):
        path = self.root / "generic.csv"
        rows = []
        for idx in range(11):
            rows.append({
                "timestamp": f"2026-01-01 00:00:{idx:02d}",
                "hostname": "CSVHOST",
                "username": f"csvuser{idx}",
                "src_ip": f"192.0.2.{idx + 1}",
                "dst_ip": f"198.51.100.{idx + 1}",
                "src_port": str(6000 + idx),
                "dst_port": "443",
                "command line": f"tool.exe --value \"quoted,{idx}\"",
                "path": f"/tmp/file,{idx}.txt",
                "blank": "",
            })
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()), lineterminator="\r\n")
            writer.writeheader()
            writer.writerows(rows)
        return path

    def _write_sonicwall(self):
        path = self.root / "sonicwall.csv"
        headers = list(SonicWallCSVParser.EXPECTED_COLUMNS)
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=headers)
            writer.writeheader()
            for idx in range(11):
                row = {header: "" for header in headers}
                row.update({
                    "Time": f"01/01/2026 00:00:{idx:02d}",
                    "ID": str(10000 + idx),
                    "Category": "Firewall",
                    "Group": "Access",
                    "Event": "Connection Opened",
                    "Priority": "Informational",
                    "Src. IP": f"192.0.2.{idx + 1}",
                    "Src. Port": str(7000 + idx),
                    "Dst. IP": f"198.51.100.{idx + 1}",
                    "Dst. Port": "443",
                    "IP Protocol": "TCP",
                    "User Name": f"sonic{idx}",
                    "FW Action": "Allow",
                    "Message": f"Allowed connection {idx}",
                })
                writer.writerow(row)
        return path

    def _run_process(self, class_name, path, attempt_id=ATTEMPT_A, hashseed="1", batch_size=BATCH_SIZE):
        candidate = CERTIFIED_CANDIDATES[class_name]
        env = {
            **os.environ,
            "SECRET_KEY": "phase1b-c1-subprocess",
            "PYTHONHASHSEED": hashseed,
        }
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                PROCESS_SNIPPET,
                candidate["module"],
                class_name,
                str(path),
                attempt_id,
                str(batch_size),
            ],
            cwd="/opt/casescope",
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
        return json.loads(result.stdout)

    def test_certified_candidates_declare_expected_contracts(self):
        for class_name, candidate in CERTIFIED_CANDIDATES.items():
            parser_cls = candidate["class"]
            self.assertTrue(parser_cls.supports_manifest_protocol, class_name)
            self.assertEqual(parser_cls.manifest_ordering_contract, candidate["contract"])

    def test_independent_process_retry_and_multibatch_determinism(self):
        for class_name, path in self.fixtures.items():
            with self.subTest(parser=class_name):
                runs = [
                    self._run_process(class_name, path, ATTEMPT_A, "1"),
                    self._run_process(class_name, path, ATTEMPT_A, "7"),
                    self._run_process(class_name, path, ATTEMPT_A, "random"),
                ]
                self.assertEqual([run["count"] for run in runs], [11, 11, 11])
                self.assertTrue(all(not run["errors"] for run in runs), runs)
                baseline = runs[0]
                for run in runs[1:]:
                    self.assertEqual(run["event_rows"], baseline["event_rows"])
                    self.assertEqual(run["batch_ids"], baseline["batch_ids"])
                    self.assertEqual(run["row_hashes"], baseline["row_hashes"])
                    self.assertEqual(run["batch_hashes"], baseline["batch_hashes"])
                    self.assertEqual(run["locators"], baseline["locators"])
                    self.assertEqual(run["ordinals"], [[0, 1, 2], [0, 1, 2], [0, 1, 2], [0, 1]])

                retry = self._run_process(class_name, path, ATTEMPT_B, "7")
                self.assertNotEqual(baseline["attempt_id"], retry["attempt_id"])
                self.assertEqual(retry["event_rows"], baseline["event_rows"])
                self.assertEqual(retry["batch_ids"], baseline["batch_ids"])
                self.assertEqual(retry["row_hashes"], baseline["row_hashes"])
                self.assertEqual(retry["batch_hashes"], baseline["batch_hashes"])
                self.assertEqual(retry["locators"], baseline["locators"])

                normal_batch = self._run_process(class_name, path, ATTEMPT_A, "1", batch_size=10000)
                self.assertEqual(normal_batch["count"], 11)
                self.assertEqual(len(normal_batch["batch_ids"]), 1)


if __name__ == "__main__":
    unittest.main()

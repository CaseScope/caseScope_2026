"""Windows Server User Access Logging (SUM/UAL) parser."""
import json
import os
from datetime import datetime
from typing import Any, Dict, Generator, Iterator, List

from parsers.base import BaseParser, ParsedEvent


class SumParser(BaseParser):
    """Parse SUM/UAL ESE databases with SumECmd when available."""

    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'sum'
    SUMECMD_BIN = '/opt/casescope/bin/sumecmd'
    # UAL databases are small in practice; the cap only guards a corrupt table
    # from producing an unbounded ingest.
    MAX_ROWS_PER_TABLE = 500000

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        if not os.path.isfile(file_path):
            return False
        filename = os.path.basename(file_path).lower()
        normalized = file_path.replace('\\', '/').lower()
        return (
            filename in {'systemidentity.mdb', 'current.mdb'}
            or ('/windows/system32/logfiles/sum/' in normalized and filename.endswith('.mdb'))
            or ('/logfiles/sum/' in normalized and filename.endswith('.mdb'))
        )

    def _row_timestamp(self, row: Dict[str, Any], file_path: str) -> datetime:
        for key in ('LastSeen', 'FirstSeen', 'Timestamp', 'LastAccess', 'InsertDate', 'Created'):
            if row.get(key):
                parsed = self.parse_timestamp(row.get(key))
                if parsed:
                    return parsed
        return self.fallback_timestamp(file_path=file_path, reason='SUM record missing timestamp')

    def _run_sumecmd(self, file_path: str) -> List[Dict[str, str]]:
        try:
            from utils.ez_tools import run_tool_for_csv, staged_hive_dir

            # SumECmd has no -f option; it only scans a directory for the SUM
            # databases. The file is staged alone so a directory holding both
            # Current.mdb and SystemIdentity.mdb is not ingested twice.
            with staged_hive_dir(file_path, prefix='casescope_sum_') as sum_dir:
                return run_tool_for_csv(self.SUMECMD_BIN, ['-d', sum_dir])
        except FileNotFoundError:
            return []
        except Exception as exc:
            self.warnings.append(f'SumECmd failed, falling back to ESE records: {exc}')
            return []

    def _ese_summary_rows(self, file_path: str) -> Iterator[Dict[str, str]]:
        """Yield one row per ESE record.

        This previously emitted a single summary row per table carrying only the
        first record as a sample, so every actual SUM/UAL record was discarded.
        """
        try:
            from dissect.esedb import EseDB
        except Exception as exc:
            self.errors.append(f'Failed to parse SUM ESE database: {exc}')
            return

        try:
            with open(file_path, 'rb') as handle:
                db = EseDB(handle)
                for table in db.tables():
                    table_name = getattr(table, 'name', '')
                    columns = getattr(table, 'columns', [])
                    count = 0
                    for record in table.records():
                        if count >= self.MAX_ROWS_PER_TABLE:
                            self.warnings.append(
                                f'Table {table_name} exceeded {self.MAX_ROWS_PER_TABLE} rows; '
                                f'remaining records were not ingested'
                            )
                            break
                        values = {}
                        for col in columns:
                            try:
                                value = record.get(col.name)
                            except Exception:
                                continue
                            if value is not None:
                                values[col.name] = str(value)
                        if not values:
                            continue
                        count += 1
                        yield {
                            'Table': table_name,
                            'ParserMode': 'dissect.esedb',
                            **values,
                        }
        except Exception as exc:
            self.errors.append(f'Failed to parse SUM ESE database: {exc}')

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        if not self.can_parse(file_path):
            self.errors.append(f'Cannot parse file: {file_path}')
            return

        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        rows = self._run_sumecmd(file_path)
        if not rows:
            rows = self._ese_summary_rows(file_path)

        for row in rows:
            username = row.get('UserName') or row.get('User') or row.get('SID') or ''
            client = row.get('ClientName') or row.get('ClientIp') or row.get('IPAddress') or row.get('Address') or ''
            role = row.get('RoleName') or row.get('ProductName') or row.get('Table') or ''
            src_ip, src_ip_raw = self.normalize_ip_for_storage(client)
            extra = {
                'sum_role': role,
                'client': client,
                'parser_mode': row.get('ParserMode') or 'sumecmd',
            }
            if src_ip_raw:
                extra['src_ip_raw'] = src_ip_raw
            yield ParsedEvent(
                case_id=self.case_id,
                artifact_type=self.artifact_type,
                timestamp=self._row_timestamp(row, file_path),
                source_file=source_file,
                source_path=file_path,
                source_host=hostname,
                case_file_id=self.case_file_id,
                username=self.safe_str(username),
                remote_host=self.safe_str(client),
                src_ip=src_ip,
                event_id='sum_ual_record',
                payload_data1=role,
                raw_json=json.dumps(row, default=str),
                search_blob=self.build_search_blob(row),
                extra_fields=json.dumps(extra, default=str),
                parser_version=self.parser_version,
            )

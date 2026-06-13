"""Windows Server User Access Logging (SUM/UAL) parser."""
import json
import os
from datetime import datetime
from typing import Any, Dict, Generator, List

from parsers.base import BaseParser, ParsedEvent


class SumParser(BaseParser):
    """Parse SUM/UAL ESE databases with SumECmd when available."""

    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'sum'
    SUMECMD_BIN = '/opt/casescope/bin/sumecmd'

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
            from utils.ez_tools import run_tool_for_csv
            return run_tool_for_csv(self.SUMECMD_BIN, ['-f', file_path])
        except FileNotFoundError:
            return []
        except Exception as exc:
            self.warnings.append(f'SumECmd failed, falling back to ESE summary: {exc}')
            return []

    def _ese_summary_rows(self, file_path: str) -> List[Dict[str, str]]:
        rows = []
        try:
            from dissect.esedb import EseDB
            with open(file_path, 'rb') as handle:
                db = EseDB(handle)
                for table in db.tables():
                    count = 0
                    sample = {}
                    columns = getattr(table, 'columns', [])
                    for record in table.records():
                        count += 1
                        if not sample:
                            for col in columns:
                                try:
                                    value = record.get(col.name)
                                except Exception:
                                    value = None
                                if value is not None:
                                    sample[col.name] = str(value)
                        if count >= 100000:
                            break
                    rows.append({
                        'Table': getattr(table, 'name', ''),
                        'RowCount': str(count),
                        'ParserMode': 'dissect.esedb_summary',
                        **sample,
                    })
        except Exception as exc:
            self.errors.append(f'Failed to parse SUM ESE database: {exc}')
        return rows

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        if not self.can_parse(file_path):
            self.errors.append(f'Cannot parse file: {file_path}')
            return

        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        rows = self._run_sumecmd(file_path) or self._ese_summary_rows(file_path)

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

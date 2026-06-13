"""Registry hive transaction-log replay helpers."""
import logging
import os
import shutil
import tempfile
from contextlib import contextmanager
from typing import Generator, Optional, Tuple

from utils.ez_tools import ez_tool_available, run_ez_tool

logger = logging.getLogger(__name__)

RLA_BIN = '/opt/casescope/bin/rla'


def sibling_transaction_logs(hive_path: str) -> Tuple[Optional[str], Optional[str]]:
    """Return sibling LOG1/LOG2 paths when present."""
    candidates = []
    for suffix in ('.LOG1', '.LOG2'):
        upper = f'{hive_path}{suffix}'
        lower = f'{hive_path}{suffix.lower()}'
        if os.path.exists(upper):
            candidates.append(upper)
        elif os.path.exists(lower):
            candidates.append(lower)
        else:
            candidates.append(None)
    return candidates[0], candidates[1]


def has_transaction_logs(hive_path: str) -> bool:
    """Return True if the hive has at least one replayable transaction sidecar."""
    return any(sibling_transaction_logs(hive_path))


@contextmanager
def replayed_hive_path(hive_path: str, *, rla_bin: str = RLA_BIN) -> Generator[str, None, None]:
    """Yield a replayed hive path when RLA and transaction logs are available.

    The helper copies the hive and any sibling LOG1/LOG2 files into an isolated
    temp directory before invoking RLA. If anything fails, callers receive the
    original hive path and should continue parsing the pre-replay hive.
    """
    if not has_transaction_logs(hive_path) or not ez_tool_available(rla_bin):
        yield hive_path
        return

    temp_dir = tempfile.mkdtemp(prefix='casescope_hive_replay_')
    try:
        hive_name = os.path.basename(hive_path)
        working_hive = os.path.join(temp_dir, hive_name)
        shutil.copy2(hive_path, working_hive)

        for source_log in sibling_transaction_logs(hive_path):
            if source_log:
                shutil.copy2(source_log, os.path.join(temp_dir, os.path.basename(source_log)))

        try:
            # RLA has changed argument names across releases. The common mode is
            # a target hive file plus an output directory.
            run_ez_tool(rla_bin, ['-f', working_hive, '--out', temp_dir], timeout=1800)
        except Exception as exc:
            logger.warning('Registry hive replay failed for %s: %s', hive_path, exc)
            yield hive_path
            return

        replay_candidates = [
            os.path.join(temp_dir, name)
            for name in os.listdir(temp_dir)
            if name.lower().endswith(('.replayed', '.recovered', '.hive', '.dat', '.hve'))
        ]
        replay_candidates = [
            candidate for candidate in replay_candidates
            if os.path.isfile(candidate) and candidate != working_hive
        ]
        yield replay_candidates[0] if replay_candidates else working_hive
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

"""Helpers for invoking Eric Zimmerman tools and reading CSV outputs."""
import csv
import logging
import os
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from typing import Dict, Generator, Iterable, List, Optional

logger = logging.getLogger(__name__)


class EzToolError(RuntimeError):
    """Raised when an EZ tool exits unsuccessfully."""


@contextmanager
def ez_output_dir(prefix: str = 'casescope_ez_') -> Generator[str, None, None]:
    """Yield a temporary output directory and clean it up afterwards."""
    output_dir = tempfile.mkdtemp(prefix=prefix)
    try:
        yield output_dir
    finally:
        shutil.rmtree(output_dir, ignore_errors=True)


def ez_tool_available(binary_path: str) -> bool:
    """Return True when a configured EZ wrapper exists and is executable."""
    return bool(binary_path and os.path.isfile(binary_path) and os.access(binary_path, os.X_OK))


def run_ez_tool(binary_path: str, args: Iterable[str], *, timeout: int = 7200) -> subprocess.CompletedProcess:
    """Run an EZ tool wrapper with defensive error reporting."""
    if not ez_tool_available(binary_path):
        raise FileNotFoundError(f'EZ tool not found or not executable: {binary_path}')

    command = [binary_path, *list(args)]
    logger.debug('Running EZ tool: %s', ' '.join(command))
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or 'unknown EZ tool error').strip()
        raise EzToolError(f'{os.path.basename(binary_path)} failed: {detail[:1000]}')
    return result


def iter_csv_rows(csv_path: str) -> Generator[Dict[str, str], None, None]:
    """Yield normalized dictionary rows from an EZ CSV file."""
    with open(csv_path, 'r', encoding='utf-8-sig', errors='replace', newline='') as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            yield {
                str(key or '').strip(): str(value or '').strip()
                for key, value in row.items()
            }


def iter_csv_outputs(output_dir: str) -> Generator[Dict[str, str], None, None]:
    """Yield rows from every CSV emitted under an output directory."""
    for root, _, filenames in os.walk(output_dir):
        for filename in sorted(filenames):
            if not filename.lower().endswith('.csv'):
                continue
            yield from iter_csv_rows(os.path.join(root, filename))


def run_tool_for_csv(
    binary_path: str,
    args: Iterable[str],
    *,
    output_dir: Optional[str] = None,
    timeout: int = 7200,
) -> List[Dict[str, str]]:
    """Run an EZ tool and return all CSV rows produced in its output directory."""
    if output_dir is None:
        with ez_output_dir() as temp_output:
            run_ez_tool(binary_path, [*list(args), '--csv', temp_output], timeout=timeout)
            return list(iter_csv_outputs(temp_output))

    run_ez_tool(binary_path, [*list(args), '--csv', output_dir], timeout=timeout)
    return list(iter_csv_outputs(output_dir))

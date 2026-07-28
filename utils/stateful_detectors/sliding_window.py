"""Sliding-window aggregation over pre-aggregated authentication slots.

Both detectors grouped events straight into detection-sized buckets with
`toStartOfInterval`. That makes the window boundaries arbitrary: an attack that
begins at 01:50 and runs to 02:10 is split across two one-hour buckets, and each
half can fall under the thresholds even though the whole clears them
comfortably. A burst is also credited to whichever bucket it happens to land in
rather than measured over its own duration.

The detectors now aggregate into slots much shorter than the detection window
and slide a window across them here. Working on pre-aggregated slots keeps this
cheap - across every case in the corpus there are only about 27,000 source slots
and 22,000 account slots - and keeps the window arithmetic in plain Python where
it can be tested directly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional, Sequence


@dataclass
class ActivitySlot:
    """Authentication activity for one key during one short time slot."""

    slot_start: datetime
    failures: int
    successes: int
    attempts: int
    peers: frozenset          # usernames for a source, or sources for an account
    first_event: Optional[datetime] = None
    last_event: Optional[datetime] = None
    sample: Sequence = field(default_factory=tuple)


@dataclass
class WindowCandidate:
    """A contiguous run of slots whose combined activity clears the thresholds."""

    key: str
    window_start: datetime
    window_end: datetime
    failures: int
    successes: int
    attempts: int
    peers: frozenset
    first_event: Optional[datetime]
    last_event: Optional[datetime]
    sample: List
    slot_count: int
    # How many separate qualifying bursts this key produced across the case,
    # and their combined failure count. One finding is reported per key rather
    # than one per burst, so this carries the rest of the picture.
    burst_count: int = 1
    failures_all_bursts: int = 0

    @property
    def failure_rate(self) -> float:
        decided = self.failures + self.successes
        return (self.failures / decided) if decided else 0.0

    @property
    def duration_seconds(self) -> int:
        if not self.first_event or not self.last_event:
            return 0
        return int((self.last_event - self.first_event).total_seconds())


def _merge(slots: Sequence[ActivitySlot], key: str) -> WindowCandidate:
    peers: set = set()
    sample: List = []
    for slot in slots:
        peers.update(slot.peers)
        sample.extend(slot.sample)

    first_events = [slot.first_event for slot in slots if slot.first_event]
    last_events = [slot.last_event for slot in slots if slot.last_event]

    return WindowCandidate(
        key=key,
        window_start=slots[0].slot_start,
        window_end=slots[-1].slot_start,
        failures=sum(slot.failures for slot in slots),
        successes=sum(slot.successes for slot in slots),
        attempts=sum(slot.attempts for slot in slots),
        peers=frozenset(peers),
        first_event=min(first_events) if first_events else None,
        last_event=max(last_events) if last_events else None,
        sample=sample,
        slot_count=len(slots),
    )


def find_window_candidates(
    *,
    key: str,
    slots: Sequence[ActivitySlot],
    window: timedelta,
    min_failures: int = 0,
    min_peers: int = 0,
    min_failure_rate: float = 0.0,
) -> List[WindowCandidate]:
    """Slide `window` across `slots` and return the qualifying windows.

    Overlapping qualifying windows are collapsed into the single widest one, so
    one burst yields one candidate rather than one per window position.
    """
    if not slots:
        return []

    ordered = sorted(slots, key=lambda slot: slot.slot_start)
    qualifying: List[WindowCandidate] = []

    start_index = 0
    for start_index in range(len(ordered)):
        window_deadline = ordered[start_index].slot_start + window

        end_index = start_index
        while (
            end_index + 1 < len(ordered)
            and ordered[end_index + 1].slot_start < window_deadline
        ):
            end_index += 1

        candidate = _merge(ordered[start_index:end_index + 1], key)
        if _qualifies(candidate, min_failures, min_peers, min_failure_rate):
            qualifying.append(candidate)

    return _collapse_overlaps(qualifying, key)


def _qualifies(
    candidate: WindowCandidate,
    min_failures: int,
    min_peers: int,
    min_failure_rate: float,
) -> bool:
    if candidate.failures < min_failures:
        return False
    if len(candidate.peers) < min_peers:
        return False
    if candidate.failure_rate < min_failure_rate:
        return False
    return True


def _collapse_overlaps(
    candidates: List[WindowCandidate], key: str
) -> List[WindowCandidate]:
    """Merge qualifying windows that overlap in time into one candidate each."""
    if not candidates:
        return []

    ordered = sorted(candidates, key=lambda c: (c.window_start, c.window_end))
    collapsed: List[WindowCandidate] = []
    current = ordered[0]

    for candidate in ordered[1:]:
        if candidate.window_start <= current.window_end:
            current = _combine(current, candidate, key)
        else:
            collapsed.append(current)
            current = candidate

    collapsed.append(current)
    return collapsed


def _combine(
    left: WindowCandidate, right: WindowCandidate, key: str
) -> WindowCandidate:
    """Combine two overlapping candidates without double-counting shared slots.

    Overlapping windows share slots, so summing their counts would inflate the
    totals. The wider window already contains the narrower one's activity
    whenever it spans it, so the larger set of counts is taken rather than added.
    """
    first_events = [event for event in (left.first_event, right.first_event) if event]
    last_events = [event for event in (left.last_event, right.last_event) if event]

    dominant = left if left.attempts >= right.attempts else right

    return WindowCandidate(
        key=key,
        window_start=min(left.window_start, right.window_start),
        window_end=max(left.window_end, right.window_end),
        failures=max(left.failures, right.failures),
        successes=max(left.successes, right.successes),
        attempts=max(left.attempts, right.attempts),
        peers=frozenset(left.peers | right.peers),
        first_event=min(first_events) if first_events else None,
        last_event=max(last_events) if last_events else None,
        sample=dominant.sample,
        slot_count=max(left.slot_count, right.slot_count),
    )


def collapse_to_strongest(candidates: Sequence[WindowCandidate]) -> Optional[WindowCandidate]:
    """Reduce one key's qualifying windows to its single strongest burst.

    An account targeted repeatedly over a case produces a qualifying window per
    burst - one account in the corpus produces sixteen. Reporting each as its
    own finding would bury the analyst, and leaving them to the finding
    deduplicator produced a summary reading "also detected as: brute_force,
    brute_force, brute_force". The strongest burst is reported instead, carrying
    a count of the others.
    """
    if not candidates:
        return None

    strongest = max(candidates, key=lambda c: (c.failures, c.attempts))
    strongest.burst_count = len(candidates)
    strongest.failures_all_bursts = sum(c.failures for c in candidates)
    return strongest


def group_slots_by_key(rows: Iterable[Sequence], key_index: int = 0) -> Dict[str, List[ActivitySlot]]:
    """Turn slot query rows into `ActivitySlot` lists keyed by their first column.

    Rows are expected in the column order the slot queries select: key,
    slot_start, failures, successes, attempts, peers, first_event, last_event,
    attempt_sample.
    """
    grouped: Dict[str, List[ActivitySlot]] = {}

    for row in rows:
        key = str(row[key_index])
        peers = row[5] or ()
        grouped.setdefault(key, []).append(
            ActivitySlot(
                slot_start=row[1],
                failures=int(row[2] or 0),
                successes=int(row[3] or 0),
                attempts=int(row[4] or 0),
                peers=frozenset(peer for peer in peers if peer),
                first_event=row[6],
                last_event=row[7],
                sample=tuple(row[8] or ()),
            )
        )

    return grouped


def ordered_intervals(sample: Sequence) -> List[float]:
    """Seconds between consecutive attempts, from a (timestamp, peer) sample.

    The samples were previously collected as two independent `groupArray` calls,
    so the timestamps and the usernames were not in a common order and the
    intervals were computed across an arbitrary permutation. Pairing them in a
    tuple and sorting here makes the interval sequence real.
    """
    timestamps = []
    for entry in sample:
        moment = entry[0] if isinstance(entry, (tuple, list)) else entry
        if isinstance(moment, datetime):
            timestamps.append(moment)

    timestamps.sort()

    intervals = []
    for earlier, later in zip(timestamps, timestamps[1:]):
        seconds = (later - earlier).total_seconds()
        if 0 < seconds < 3600:
            intervals.append(seconds)
    return intervals


def peers_from_sample(sample: Sequence) -> List[Any]:
    """Peer values from a (timestamp, peer) sample, in time order."""
    entries = [
        entry for entry in sample
        if isinstance(entry, (tuple, list)) and len(entry) > 1
    ]
    entries.sort(key=lambda entry: entry[0])
    return [entry[1] for entry in entries if entry[1]]

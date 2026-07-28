"""Peer deviation statistics for behavioral comparison.

Three properties matter for comparing an entity against its peer group, and the
original implementation had none of them:

Leave-one-out. The entity being scored was part of the median and spread it was
measured against, so in a group of a handful of members a single compromised
account pulled the centre toward itself and inflated the spread it had to beat.

A consistent centre and spread. Deviation was computed as
``(value - median) / stdev``, pairing a robust centre with a non-robust spread.
One high-volume service account in a cluster produced a median near zero and a
standard deviation in the hundreds, so no other member could ever deviate.

A threshold the group size can express. With n members, the largest deviation
any one of them can show is bounded by the sample size: around sqrt(n) in the
extreme case of one member differing from n-1 identical peers. Demanding a
deviation of 3.0 from a group of three was arithmetically impossible, so small
groups could never produce a finding no matter what the entity did. Groups too
small for a spread estimate fall back to expressing deviation as a multiple of
the peer median instead.

Scores from both methods are returned on one comparable scale, so a caller can
apply a single threshold and a single confidence model to either.
"""

from __future__ import annotations

import math
import statistics
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

# Iglewicz and Hoaglin's constant, which puts a median-absolute-deviation
# score on roughly the same scale as a standard score for normal data.
MAD_TO_SIGMA = 0.6745

# Below this many members there are too few remaining peers to estimate a
# spread, so deviation is expressed as a multiple of the peer median instead.
MIN_MEMBERS_FOR_SPREAD_ESTIMATE = 5

# A value this many times the peer median counts as a full-threshold deviation
# under the ratio fallback.
DEFAULT_RATIO_THRESHOLD = 3.0

# Deviation scores are capped so one extreme metric cannot dominate a composite.
MAX_DEVIATION_SCORE = 10.0

METHOD_MODIFIED_ZSCORE = 'modified_zscore'
METHOD_RATIO = 'ratio_to_peer_median'
METHOD_NO_COMPARISON = 'no_comparison_possible'
METHOD_BELOW_FLOOR = 'below_absolute_floor'


@dataclass
class PeerDeviation:
    """One metric's deviation of an entity from its peers."""

    metric: str
    value: float
    peer_median: float
    peer_spread: float
    score: float
    method: str
    threshold: float
    exceeded: bool
    peer_count: int

    def as_details(self) -> Dict[str, Any]:
        return {
            'value': round(self.value, 2),
            'peer_median': round(self.peer_median, 2),
            'peer_spread': round(self.peer_spread, 4),
            'score': round(self.score, 2),
            'method': self.method,
            'threshold': round(self.threshold, 2),
            'peer_count': self.peer_count,
            'direction': 'high' if self.value >= self.peer_median else 'low',
        }


@dataclass
class PeerMetricBaseline:
    """Median and robust spread for one metric across a peer group."""

    metric: str
    median: float
    mad: float
    values: List[float] = field(default_factory=list)

    def as_summary(self) -> Dict[str, Any]:
        return {
            'median': round(self.median, 2),
            'mad': round(self.mad, 4),
            'count': len(self.values),
        }


def max_attainable_score(member_count: int) -> float:
    """Largest deviation score any single member of a group can reach.

    For n values the most extreme member sits at most (n-1)/sqrt(n) standard
    deviations from the mean, and about sqrt(n) from the median in the extreme
    case of n-1 identical peers. The looser of the two is used so the ceiling
    never rejects a deviation that is genuinely reachable.
    """
    if member_count < 2:
        return 0.0
    return max(math.sqrt(member_count), (member_count - 1) / math.sqrt(member_count))


def resolve_threshold(member_count: int, configured_threshold: float) -> Optional[float]:
    """Return a threshold the group size can actually express, or None.

    None means the group is too small for any peer comparison to carry meaning.
    """
    if member_count < 2:
        return None

    ceiling = max_attainable_score(member_count)
    if ceiling <= 0:
        return None

    # Keep a margin below the arithmetic ceiling so the threshold is reachable
    # by more than the single most extreme arrangement of values.
    reachable = ceiling * 0.8
    return min(float(configured_threshold), reachable)


def median_absolute_deviation(values: Sequence[float]) -> float:
    """Median of absolute deviations from the median."""
    if not values:
        return 0.0
    center = statistics.median(values)
    return statistics.median([abs(value - center) for value in values])


def build_metric_baseline(metric: str, values: Sequence[Optional[float]]) -> PeerMetricBaseline:
    """Summarize one metric across a peer group, ignoring members it cannot describe."""
    numeric = [float(value) for value in values if value is not None]
    if not numeric:
        return PeerMetricBaseline(metric=metric, median=0.0, mad=0.0, values=[])

    return PeerMetricBaseline(
        metric=metric,
        median=float(statistics.median(numeric)),
        mad=float(median_absolute_deviation(numeric)),
        values=numeric,
    )


def _ratio_score(value: float, peer_median: float, ratio_threshold: float) -> float:
    """Express a value as a deviation score based on its ratio to the peer median.

    Used when the group is too small for a spread estimate, or when every peer
    reports an identical value so the spread is zero.
    """
    baseline = max(abs(peer_median), 1.0)
    ratio = abs(value - peer_median) / baseline
    if ratio <= 0:
        return 0.0

    threshold = ratio_threshold if ratio_threshold > 0 else DEFAULT_RATIO_THRESHOLD
    # Scale so that hitting the ratio threshold scores the same as hitting the
    # configured deviation threshold, keeping both methods comparable.
    return min(MAX_DEVIATION_SCORE, DEFAULT_RATIO_THRESHOLD * ratio / threshold)


def compute_peer_deviation(
    *,
    metric: str,
    value: Optional[float],
    peer_values: Sequence[float],
    configured_threshold: float,
    ratio_threshold: float = DEFAULT_RATIO_THRESHOLD,
    min_absolute_difference: float = 0.0,
    log_scale: bool = False,
) -> PeerDeviation:
    """Score one entity against its peers on one metric, leaving it out.

    `peer_values` must exclude the entity being scored. A value of None means
    the metric does not apply to that member, and such members take no part in
    the baseline: an account with no authentication at all would otherwise pull
    every authentication median toward zero and make its peers look anomalous.
    """
    others = [float(peer) for peer in peer_values if peer is not None]
    peer_count = len(others)
    member_count = peer_count + 1

    threshold = resolve_threshold(member_count, configured_threshold)
    if value is None or threshold is None or peer_count == 0:
        return PeerDeviation(
            metric=metric,
            value=float(value or 0),
            peer_median=0.0,
            peer_spread=0.0,
            score=0.0,
            method=METHOD_NO_COMPARISON,
            threshold=float(configured_threshold),
            exceeded=False,
            peer_count=peer_count,
        )

    entity_value = float(value)
    peer_median = float(statistics.median(others))
    peer_mad = float(median_absolute_deviation(others))

    # Statistical significance is not the same as practical significance. In a
    # tightly grouped population the robust spread is near zero, so accessing
    # two hosts where the peer median is one scores as a large deviation. A
    # per-metric floor keeps differences too small to matter out of the results.
    if min_absolute_difference and abs(entity_value - peer_median) < min_absolute_difference:
        return PeerDeviation(
            metric=metric,
            value=entity_value,
            peer_median=peer_median,
            peer_spread=peer_mad,
            score=0.0,
            method=METHOD_BELOW_FLOOR,
            threshold=threshold,
            exceeded=False,
            peer_count=peer_count,
        )

    # Event counts are lognormal rather than normal: a handful of service
    # accounts sit orders of magnitude above the median. Measured on the raw
    # scale the whole upper tail clears any threshold, so counts are compared
    # in log space while bounded percentages stay linear.
    if log_scale:
        scored_value = math.log1p(max(entity_value, 0.0))
        scored_peers = [math.log1p(max(peer, 0.0)) for peer in others]
        scored_median = float(statistics.median(scored_peers))
        scored_spread = float(median_absolute_deviation(scored_peers))
    else:
        scored_value = entity_value
        scored_median = peer_median
        scored_spread = peer_mad

    if member_count >= MIN_MEMBERS_FOR_SPREAD_ESTIMATE and scored_spread > 0:
        method = METHOD_MODIFIED_ZSCORE
        score = MAD_TO_SIGMA * (scored_value - scored_median) / scored_spread
        score = max(-MAX_DEVIATION_SCORE, min(MAX_DEVIATION_SCORE, score))
    else:
        method = METHOD_RATIO
        signed = 1.0 if entity_value >= peer_median else -1.0
        score = signed * _ratio_score(entity_value, peer_median, ratio_threshold)

    return PeerDeviation(
        metric=metric,
        value=entity_value,
        peer_median=peer_median,
        peer_spread=peer_mad,
        score=score,
        method=method,
        threshold=threshold,
        exceeded=abs(score) >= threshold,
        peer_count=peer_count,
    )


def compute_group_deviations(
    *,
    metric_values: Dict[str, List[Optional[float]]],
    entity_index: int,
    configured_threshold: float,
    ratio_threshold: float = DEFAULT_RATIO_THRESHOLD,
    absolute_floors: Optional[Dict[str, float]] = None,
    log_scaled_metrics: Optional[Sequence[str]] = None,
) -> Dict[str, PeerDeviation]:
    """Score one member of a group across every metric, leaving it out.

    `metric_values` maps a metric name to that metric's value for every member
    of the group, in a stable order; `entity_index` selects the member. A None
    entry means the metric does not apply to that member. `absolute_floors`
    gives the smallest difference from the peer median that counts as a
    deviation for each metric, and `log_scaled_metrics` names the metrics
    compared in log space.
    """
    floors = absolute_floors or {}
    log_scaled = set(log_scaled_metrics or ())
    deviations: Dict[str, PeerDeviation] = {}
    for metric, values in metric_values.items():
        if entity_index >= len(values):
            continue
        peers = [value for index, value in enumerate(values) if index != entity_index]
        deviations[metric] = compute_peer_deviation(
            metric=metric,
            value=values[entity_index],
            peer_values=peers,
            configured_threshold=configured_threshold,
            ratio_threshold=ratio_threshold,
            min_absolute_difference=floors.get(metric, 0.0),
            log_scale=metric in log_scaled,
        )
    return deviations

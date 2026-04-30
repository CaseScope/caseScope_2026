from datetime import datetime, timezone
from types import SimpleNamespace

from utils.ai_audit import (
    build_record_metadata,
    canonical_json,
    compute_content_hash,
    compute_record_hash,
    timestamp_for_hash,
    verify_ai_audit_chain,
)


def test_ai_audit_canonical_json_contract():
    payload = {"z": "last", "a": "first", "nested": {"b": 2, "a": 1}}

    assert canonical_json(payload) == '{"a":"first","nested":{"a":1,"b":2},"z":"last"}'


def test_ai_audit_v1_hash_contract():
    timestamp = datetime(2026, 4, 30, 20, 52, 0, tzinfo=timezone.utc)
    prompt_hash = compute_content_hash("Investigate HOST_0001")
    response_hash = compute_content_hash("HOST_0001 shows suspicious login activity")
    metadata = build_record_metadata(
        timestamp=timestamp,
        case_uuid="case-123",
        function="report",
        provider_type="openai",
        model="gpt-4o",
        user_id=42,
        status="success",
        response_complete=True,
        prompt_hash=prompt_hash,
        response_hash=response_hash,
        previous_record_hash="v1:0000000000000000000000000000000000000000000000000000000000000000",
    )

    assert timestamp_for_hash(timestamp) == "2026-04-30T20:52:00Z"
    assert prompt_hash == "v1:7cf7fc9aca4c012461aee6845a3dd0a7e0d18261cca0a050ce509271c1f26bad"
    assert response_hash == "v1:b870b1c1140c6c6f509bf88df27e540d0672669720eef31da1bbda4837d135c0"
    assert compute_record_hash(metadata) == "v1:4a67f0329bb0fde5c7ee379e74210e2d129d63ac0b13325c21bfa852950bcca4"


class _FakeQuery:
    def __init__(self, records):
        self.records = records

    def order_by(self, *_args, **_kwargs):
        return self

    def all(self):
        return self.records


def _record(record_id, timestamp, prompt, response, previous_hash):
    prompt_hash = compute_content_hash(prompt)
    response_hash = compute_content_hash(response)
    metadata = build_record_metadata(
        timestamp=timestamp,
        case_uuid="case-123",
        function="report",
        provider_type="openai",
        model="gpt-4o",
        user_id=42,
        status="success",
        response_complete=True,
        prompt_hash=prompt_hash,
        response_hash=response_hash,
        previous_record_hash=previous_hash,
    )
    record_hash = compute_record_hash(metadata)
    return SimpleNamespace(
        id=record_id,
        timestamp=timestamp,
        case_uuid="case-123",
        function="report",
        provider_type="openai",
        model="gpt-4o",
        user_id=42,
        status="success",
        response_complete=True,
        request_payload=prompt,
        response_payload=response,
        prompt_hash=prompt_hash,
        response_hash=response_hash,
        previous_record_hash=previous_hash,
        record_hash=record_hash,
    )


def test_ai_audit_chain_verification_detects_clean_chain():
    timestamp = datetime(2026, 4, 30, 20, 52, 0, tzinfo=timezone.utc)
    first = _record(1, timestamp, "Prompt 1", "Response 1", None)
    second = _record(2, timestamp, "Prompt 2", "Response 2", first.record_hash)

    result = verify_ai_audit_chain(query=_FakeQuery([first, second]))

    assert result["valid"] is True
    assert result["record_count_checked"] == 2
    assert result["previous_record_hash"] == second.record_hash


def test_ai_audit_chain_verification_reports_first_inconsistency():
    timestamp = datetime(2026, 4, 30, 20, 52, 0, tzinfo=timezone.utc)
    first = _record(1, timestamp, "Prompt 1", "Response 1", None)
    second = _record(2, timestamp, "Prompt 2", "Response 2", first.record_hash)
    second.record_hash = "v1:bad"

    result = verify_ai_audit_chain(query=_FakeQuery([first, second]))

    assert result["valid"] is False
    assert result["first_inconsistent_record_id"] == 2
    assert result["actual_hash"] == "v1:bad"

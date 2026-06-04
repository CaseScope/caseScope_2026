import importlib.util
import json
import os
import tempfile
import unittest


REPO_ROOT = os.path.dirname(os.path.dirname(__file__))


def _load_module(name: str, relative_path: str):
    module_path = os.path.join(REPO_ROOT, relative_path)
    spec = importlib.util.spec_from_file_location(name, module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


eval_helper = _load_module(
    'eval_harness_ai_adjudication_eval',
    os.path.join('utils', 'ai_adjudication_eval.py'),
)


class AIAdjudicationEvalHarnessTestCase(unittest.TestCase):
    def test_eval_record_contains_required_fields_without_mutating_inputs(self):
        raw_payload = {
            'confidence_adjustment': 4,
            'supporting_evidence_ids': ['evidence:anchor'],
            'mitigating_evidence_ids': [],
            'referenced_context_ids': ['context:known_good'],
            'model': 'raw-model',
        }
        ai_result = {
            'adjustment': 0,
            'model_used': 'validated-model',
            'adjudication_validation': {
                'is_valid': False,
                'errors': ['error'],
                'warnings': ['warning'],
                'unsupported_fact_claims': ['known-good'],
                'invalid_evidence_ids': ['evidence:missing'],
                'invalid_context_ids': ['context:missing'],
            },
        }
        raw_before = json.dumps(raw_payload, sort_keys=True)
        result_before = json.dumps(ai_result, sort_keys=True)

        record = eval_helper.build_ai_adjudication_eval_record(
            case_label='rdp-positive',
            pattern_id='rdp_lateral',
            deterministic_score=58,
            raw_payload=raw_payload,
            ai_result=ai_result,
            noise_context_state='unknown',
        )

        for field in [
            'case_label',
            'pattern_id',
            'deterministic_score',
            'raw_adjustment',
            'validated_adjustment',
            'final_score_if_available',
            'valid',
            'validation_errors',
            'validation_warnings',
            'unsupported_fact_claims',
            'invalid_evidence_ids',
            'invalid_context_ids',
            'referenced_context_ids',
            'supporting_evidence_ids',
            'mitigating_evidence_ids',
            'noise_context_state',
            'model_used',
            'timestamp_utc',
        ]:
            self.assertIn(field, record)

        self.assertEqual(record['raw_adjustment'], 4)
        self.assertEqual(record['validated_adjustment'], 0)
        self.assertFalse(record['valid'])
        self.assertEqual(record['validation_errors'], ['error'])
        self.assertEqual(record['validation_warnings'], ['warning'])
        self.assertEqual(record['unsupported_fact_claims'], ['known-good'])
        self.assertEqual(record['invalid_evidence_ids'], ['evidence:missing'])
        self.assertEqual(record['invalid_context_ids'], ['context:missing'])
        self.assertEqual(record['referenced_context_ids'], ['context:known_good'])
        self.assertEqual(record['supporting_evidence_ids'], ['evidence:anchor'])
        self.assertEqual(record['model_used'], 'validated-model')
        self.assertTrue(record['timestamp_utc'].endswith('Z'))
        self.assertEqual(json.dumps(raw_payload, sort_keys=True), raw_before)
        self.assertEqual(json.dumps(ai_result, sort_keys=True), result_before)

    def test_jsonl_writer_writes_valid_lines_and_returns_count(self):
        records = [
            {'case_label': 'one', 'valid': True},
            {'case_label': 'two', 'valid': False},
        ]
        original_records = json.loads(json.dumps(records))

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, 'nested', 'records.jsonl')
            written = eval_helper.write_eval_records_jsonl(records, path)

            self.assertEqual(written, 2)
            with open(path, 'r', encoding='utf-8') as handle:
                lines = [json.loads(line) for line in handle if line.strip()]

        self.assertEqual(lines, records)
        self.assertEqual(records, original_records)


if __name__ == '__main__':
    unittest.main()

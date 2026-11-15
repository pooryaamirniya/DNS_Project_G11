"""Independent unit tests for Quality Gate; no Docker, no dangerous native code."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SCRIPT=Path(__file__).resolve().parent.parent/'tools'/'quality_gate.py'
SPEC=importlib.util.spec_from_file_location('quality_gate',SCRIPT)
module=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)

class GateChecks(unittest.TestCase):
    def test_known_six_scenario_codes(self):
        self.assertEqual(len(module.EXPECTED),6)
        self.assertEqual(module.EXPECTED['cjsonreal-regression'],20)

    def test_unknown_modes_have_five_distinct_exit_codes(self):
        self.assertEqual(set(module.MODE_EXIT.values()),{0,10,20,30,40})

    def test_source_tampering_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/'test.c').write_bytes(b'correct')
            checker=module.Gate(root)
            checker.source('test.c',module.sha256(b'correct'),'source-ok')
            checker.source('test.c',module.sha256(b'changed'),'source-tampered')
            self.assertTrue(checker.checks[0]['ok'])
            self.assertFalse(checker.checks[1]['ok'])

    def test_path_traversal_disallowed(self):
        with tempfile.TemporaryDirectory() as tmp:
            checker=module.Gate(Path(tmp))
            checker.source('../../etc/passwd','0'*64,'path')
            self.assertFalse(checker.checks[0]['ok'])

    def test_missing_report_returns_error_not_false_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            checker=module.Gate(Path(tmp))
            checker.official_matrix()
            self.assertEqual(checker.save(),1)
            report=json.loads((Path(tmp)/'artifacts/quality-gate/quality_report.json').read_text())
            self.assertGreater(report['errors'],0)

    def test_strict_warnings_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            checker=module.Gate(Path(tmp),strict=True)
            checker.add('unknown-correlation',False,'Need runtime evidence',warning=True)
            self.assertEqual(checker.save(),1)

if __name__ == '__main__':
    unittest.main()

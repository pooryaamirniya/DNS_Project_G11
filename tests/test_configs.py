import json
from pathlib import Path
import unittest
from patchguard.cli import ROOT, input_bytes

class ConfigTests(unittest.TestCase):
    def test_scenarios_have_expected_oracles_and_sources(self):
        found=list((ROOT/'configs').glob('*.json'))
        self.assertGreaterEqual(len(found),6)
        for path in found:
            cfg=json.loads(path.read_text())
            self.assertTrue((ROOT/cfg['base']).is_file())
            self.assertTrue((ROOT/cfg['patch']).is_file())
            self.assertTrue((ROOT/cfg['reference']).is_file())
            self.assertGreaterEqual(len(cfg['attacks']),2)
            self.assertGreaterEqual(len(cfg['functional']),4)
            for case in cfg['attacks']+cfg['functional']:
                self.assertIsInstance(input_bytes(case),bytes)
                self.assertIn('exit_code',case['expected'])
                self.assertIn('stdout',case['expected'])

if __name__=='__main__':
    unittest.main()

class RegressionTests(unittest.TestCase):
    def test_learned_cases_are_loaded_for_subsequent_pipelines(self):
        from patchguard.cli import load_persisted_regressions
        for target in ('frame','jsonc'):
            learned=load_persisted_regressions(ROOT,target)
            self.assertGreaterEqual(len(learned),2)
            for case in learned:
                self.assertTrue(case['persisted'])
                self.assertTrue(input_bytes(case))
                self.assertEqual(case['expected']['exit_code'],2)

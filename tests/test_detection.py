import unittest
from patchguard.detection import detect, signature, expected_behavior
from patchguard.minimize import ddmin
from patchguard.hardening import compare
from patchguard.cli import crash_consensus


def observation(stderr='',code=0,timeout=False):
    return {'stderr':stderr,'stdout':'','returncode':code,'timeout':timeout}


class DetectionTests(unittest.TestCase):
    def test_memory_finding_prefers_application_frame(self):
        err=('ERROR: AddressSanitizer: heap-buffer-overflow\n'
             '    #0 0x123 in memcpy sanitizer_common:12\n'
             '    #1 0x456 in save_note /repo/targets/jsonc/base.c:15\n')
        result=detect(observation(err,-6))
        self.assertTrue(result['confirmed'])
        self.assertEqual(result['error_type'],'heap-buffer-overflow')
        self.assertEqual(result['function'],'save_note')

    def test_crash_without_sanitizer_is_unclassified(self):
        result=detect(observation('segmentation fault',-11))
        self.assertFalse(result['confirmed'])
        self.assertEqual(result['mechanism'],'OS signal (unclassified)')

    def test_three_replays_required(self):
        err='ERROR: AddressSanitizer: stack-buffer-overflow\n'
        good={'finding':detect(observation(err,-6))}
        no={'finding':detect(observation('',0))}
        self.assertEqual(crash_consensus([good,good,good])[0],'confirmed')
        self.assertEqual(crash_consensus([good,no,good])[0],'inconclusive')

    def test_invalid_stdout_not_only_exit_code(self):
        self.assertFalse(expected_behavior(observation(code=0), {'exit_code':0,'stdout':'OK\n'}))

    def test_delta_preserves_predicate(self):
        shortest,attempts=ddmin(b'prefix:AAAAAAA:trailer',lambda b: b'AAA' in b)
        self.assertIn(b'AAA',shortest)
        self.assertLess(len(shortest),len(b'prefix:AAAAAAA:trailer'))
        self.assertGreater(attempts,0)

    def test_hardening_drops(self):
        a={'NX':True,'PIE':True,'RELRO':'Full','Canary_symbol':True}
        b={'NX':False,'PIE':True,'RELRO':'Partial','Canary_symbol':True}
        self.assertEqual(len(compare(a,b)),2)


if __name__=='__main__':
    unittest.main()

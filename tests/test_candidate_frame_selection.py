import unittest

from patchguard.detection import detect, signature


class CandidateFrameSelectionTests(unittest.TestCase):

    def make_result(self, source):
        stderr = f"""
=================================================================
==51==ERROR: AddressSanitizer: stack-buffer-overflow
WRITE of size 25

    #0 0x1234 in memcpy ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors_memintrinsics.inc:115
    #1 0x5678 in process_message {source}:12
    #2 0x9999 in main {source}:22
"""

        return {
            "stderr": stderr,
            "stdout": "",
            "returncode": -6,
            "timeout": False,
        }

    def test_original_target(self):
        result = detect(
            self.make_result("/work/targets/frame/base.c")
        )

        self.assertTrue(result["confirmed"])
        self.assertEqual(
            result["function"],
            "process_message"
        )

    def test_unknown_candidate(self):
        result = detect(
            self.make_result(
                "/work/artifacts/blind-patches/candidates/random_patch.c"
            )
        )

        self.assertTrue(result["confirmed"])
        self.assertEqual(
            result["function"],
            "process_message"
        )

    def test_same_vulnerability_signature(self):
        base = detect(
            self.make_result("/work/targets/frame/base.c")
        )

        patched = detect(
            self.make_result(
                "/work/artifacts/blind-patches/candidates/random_patch.c"
            )
        )

        self.assertEqual(
            signature(base),
            signature(patched)
        )


if __name__ == "__main__":
    unittest.main()

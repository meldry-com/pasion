import json
import unittest

from clippy_gate import diagnostics


def warning(line=1, source="unsafe { call() }", target="lib"):
    return json.dumps({
        "reason": "compiler-message",
        "target": {"name": "example", "kind": [target]},
        "message": {
            "level": "warning", "code": {"code": "unsafe_code"},
            "message": "usage of an unsafe block",
            "spans": [{"is_primary": True, "file_name": "src/lib.rs",
                       "line_start": line, "text": [{"text": source}]}],
        },
    })


class DiagnosticGateTests(unittest.TestCase):
    def test_existing_warning_may_move_without_failing(self):
        self.assertFalse(diagnostics([warning(20)]) - diagnostics([warning(1)]))

    def test_new_normally_denied_diagnostic_fails(self):
        self.assertTrue(diagnostics([warning()]) - diagnostics([]))

    def test_second_occurrence_is_not_grandfathered(self):
        self.assertTrue(diagnostics([warning(), warning(20)]) - diagnostics([warning()]))

    def test_different_source_is_a_new_diagnostic(self):
        self.assertTrue(diagnostics([warning(source="unsafe { other() }")])
                        - diagnostics([warning()]))

    def test_duplicate_build_targets_do_not_change_counts(self):
        self.assertEqual(diagnostics([warning(), warning(target="test")]),
                         diagnostics([warning()]))


if __name__ == "__main__":
    unittest.main()

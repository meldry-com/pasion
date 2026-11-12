import json
import contextlib
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from clippy_gate import comparison_base, diagnostics, lint


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
    def test_merge_preview_uses_current_base_instead_of_stale_event(self):
        with patch("clippy_gate.subprocess.check_output", return_value="preview current-main pr-head\n"):
            self.assertEqual(comparison_base(Path("."), "old-main", "pr-head"), "current-main")

    def test_unrelated_merge_cannot_override_requested_base(self):
        with patch("clippy_gate.subprocess.check_output", side_effect=["author-merge hidden-base other-head\n", "event-base\n"]):
            self.assertEqual(comparison_base(Path("."), "event-base", "pr-head"), "event-base")

    def test_push_uses_the_explicit_previous_revision(self):
        with patch("clippy_gate.subprocess.check_output", return_value="previous\n") as git:
            self.assertEqual(comparison_base(Path("."), "previous", ""), "previous")
            self.assertIn("previous^{commit}", git.call_args.args[0])

    def test_cargo_failure_preserves_compiler_details_for_either_checkout(self):
        for checkout in ("base", "head"):
            with self.subTest(checkout=checkout), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "diagnostics.jsonl"
                rendered = f"error[E0308]: mismatched types\n --> {checkout}/src/lib.rs:7:9"

                def failing_cargo(command, **kwargs):
                    json.dump({"reason": "compiler-message", "message": {
                        "message": "mismatched types", "rendered": rendered,
                    }}, kwargs["stdout"])
                    kwargs["stdout"].write("\n")
                    return subprocess.CompletedProcess(command, 101)

                captured = io.StringIO()
                with patch("clippy_gate.subprocess.run", side_effect=failing_cargo), contextlib.redirect_stderr(captured):
                    with self.assertRaises(subprocess.CalledProcessError) as error:
                        lint(Path(checkout), output)
                self.assertEqual(error.exception.returncode, 101)
                self.assertIn(rendered, captured.getvalue())

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

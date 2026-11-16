import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("check-publish-ref.py")
ROOT = SCRIPT.resolve().parents[2]
FIRST = "a" * 40
SECOND = "b" * 40
PUBLISH_GATE = "steps.publish_ref.outputs.publish == 'true'"
LOCAL_OR_PUBLISH = f"github.event_name == 'pull_request' || {PUBLISH_GATE}"


def workflow_job(text, name):
    """Read a top-level job without adding a YAML dependency to the test gate."""
    match = re.search(rf"^  {re.escape(name)}:\n(.*?)(?=^  [\w-]+:\n|\Z)", text, re.M | re.S)
    if not match:
        raise AssertionError(f"Missing workflow job: {name}")
    return match.group(1)


def workflow_steps(job):
    return re.split(r"^      - ", job.split("    steps:\n", 1)[1], flags=re.M)[1:]


def condition(step):
    lines = step.splitlines()
    for index, line in enumerate(lines):
        if line.startswith("        if: "):
            value = line.removeprefix("        if: ")
            if value != "|":
                return value
            continuation = []
            for line in lines[index + 1:]:
                if not line.startswith("          "):
                    break
                continuation.append(line.strip())
            return " ".join(continuation)
    return None


class PublicationRefTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.reply = self.root / "reply.json"
        self.calls = self.root / "calls.jsonl"
        self.output = self.root / "output"
        fake = self.root / "gh"
        fake.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, pathlib, sys\n"
            "with pathlib.Path(os.environ['PASION_TEST_CALLS']).open('a') as stream:\n"
            "    stream.write(json.dumps(sys.argv[1:]) + '\\n')\n"
            "sys.stdout.write(pathlib.Path(os.environ['PASION_TEST_REPLY']).read_text())\n"
            "sys.stderr.write(os.environ['GH_TOKEN'])\n"
            "sys.exit(int(os.environ.get('PASION_TEST_RETURN_CODE', '0')))\n"
        )
        fake.chmod(0o755)
        self.env = dict(
            os.environ,
            PATH=str(self.root) + os.pathsep + os.environ.get("PATH", ""),
            GH_TOKEN="test-secret-never-print",
            GITHUB_REF="refs/heads/main",
            GITHUB_SHA=FIRST,
            GITHUB_REPOSITORY="meldry-com/pasion",
            GITHUB_OUTPUT=str(self.output),
            PASION_TEST_CALLS=str(self.calls),
            PASION_TEST_REPLY=str(self.reply),
        )
        self.respond(FIRST)

    def respond(self, revision, ref="refs/heads/main"):
        self.reply.write_text(json.dumps({"ref": ref, "object": {"type": "commit", "sha": revision}}))

    def check(self, *, success=True, publish=True):
        self.output.write_text("")
        result = subprocess.run(
            [sys.executable, str(SCRIPT)], env=self.env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5,
        )
        self.assertEqual(result.returncode, 0 if success else 1, result.stderr)
        outputs = dict(line.split("=", 1) for line in self.output.read_text().splitlines())
        self.assertEqual(outputs, {"publish": str(publish).lower()})
        self.assertNotIn(self.env["GH_TOKEN"], result.stdout + result.stderr)
        return result

    def test_current_main_and_nested_release_use_typed_read_only_ref_lookup(self):
        for branch, encoded in (
            ("main", "main"),
            ("release/1.2", "release%2F1.2"),
            ("release/2026/q4", "release%2F2026%2Fq4"),
            ("release/caf\u00e9+fix", "release%2Fcaf%C3%A9%2Bfix"),
        ):
            with self.subTest(branch=branch):
                self.env["GITHUB_REF"] = f"refs/heads/{branch}"
                self.respond(FIRST, self.env["GITHUB_REF"])
                self.check()
                self.assertEqual(
                    json.loads(self.calls.read_text().splitlines()[-1]),
                    ["api", "--method", "GET", f"repos/meldry-com/pasion/git/ref/heads/{encoded}"],
                )

    def test_each_architecture_and_manifest_independently_reject_stale_branches(self):
        for branch in ("main", "release/2026/q4"):
            self.env["GITHUB_REF"] = f"refs/heads/{branch}"
            self.respond(SECOND, self.env["GITHUB_REF"])
            for stage in ("amd64", "arm64", "manifest"):
                with self.subTest(branch=branch, stage=stage):
                    result = self.check(publish=False)
                    self.assertIn("Skipping stale publication", result.stdout)
        self.assertEqual(len(self.calls.read_text().splitlines()), 6)

    def test_completed_old_main_rerun_is_stale_after_new_main_publication(self):
        self.check()
        self.respond(SECOND)
        self.env["GITHUB_SHA"] = SECOND
        self.check()
        self.env["GITHUB_SHA"] = FIRST
        self.check(publish=False)

    def test_manifest_recheck_can_reject_a_branch_advanced_after_architectures(self):
        self.check()  # amd64
        self.check()  # arm64
        self.respond(SECOND)
        self.check(publish=False)  # manifest has its own lookup
        self.assertEqual(len(self.calls.read_text().splitlines()), 3)

    def test_tags_and_other_nonmoving_refs_preserve_policy_without_api(self):
        self.env["PASION_TEST_RETURN_CODE"] = "1"
        self.reply.write_text("not a response")
        for ref in ("refs/tags/v1.2.3", "refs/tags/v1.2.4-rc.1", "refs/heads/feature/example"):
            with self.subTest(ref=ref):
                self.env["GITHUB_REF"] = ref
                self.check()
        self.assertFalse(self.calls.exists())

    def test_api_failure_leaves_gate_closed_without_echoing_credentials(self):
        self.env["PASION_TEST_RETURN_CODE"] = "1"
        self.check(success=False, publish=False)

    def test_malformed_response_never_opens_gate(self):
        for payload in ("not json", "null", "[]", "{}", json.dumps({"ref": "refs/heads/main"})):
            with self.subTest(payload=payload):
                self.reply.write_text(payload)
                self.check(success=False, publish=False)

    def test_wrong_ref_object_type_and_sha_never_open_gate(self):
        for ref, kind, revision in (
            ("refs/heads/release/other", "commit", FIRST),
            ("refs/heads/main", "tag", FIRST),
            ("refs/heads/main", "commit", None),
            ("refs/heads/main", "commit", "truncated"),
            ("refs/heads/main", "commit", 123),
        ):
            with self.subTest(ref=ref, kind=kind, revision=revision):
                self.reply.write_text(json.dumps({"ref": ref, "object": {"type": kind, "sha": revision}}))
                self.check(success=False, publish=False)

    def test_missing_or_malformed_context_never_opens_gate(self):
        for key, value in (
            ("GITHUB_REF", ""),
            ("GITHUB_REF", "refs/heads/main\ninjected=true"),
            ("GITHUB_SHA", "short"),
            ("GITHUB_REPOSITORY", "../other?bad"),
        ):
            with self.subTest(key=key):
                previous = self.env[key]
                self.env[key] = value
                self.check(success=False, publish=False)
                self.env[key] = previous
        del self.env["GITHUB_SHA"]
        self.check(success=False, publish=False)
        self.assertFalse(self.calls.exists())


class WorkflowWiringTests(unittest.TestCase):
    def setUp(self):
        self.release = (ROOT / ".github/workflows/release.yaml").read_text()

    def test_existing_cancellation_and_tag_generation_are_preserved(self):
        self.assertIn("group: build-${{ github.ref }}\n  cancel-in-progress: true", self.release)
        self.assertIn('regular_suffixes+=("${major}.${minor}" "${major}" "latest")', self.release)
        self.assertIn('if [ "$safe_ref" = "main" ]; then\n                regular_suffixes+=("latest")', self.release)

    def test_both_publish_jobs_checkout_exact_source_and_lookup_independently(self):
        for job_name in ("build-image-arch", "build-image"):
            with self.subTest(job=job_name):
                job = workflow_job(self.release, job_name)
                steps = workflow_steps(job)
                self.assertIn("actions/checkout@v7", steps[0])
                self.assertIn("ref: ${{ github.sha }}", steps[0])
                self.assertIn("persist-credentials: false", steps[0])
                self.assertIn("id: publish_ref", steps[1])
                self.assertIn("GH_TOKEN: ${{ github.token }}", steps[1])
                self.assertIn("python3 .github/scripts/check-publish-ref.py", steps[1])
                self.assertIn("contents: read", job)

    def test_pr_retains_local_build_load_and_smoke_without_ref_api(self):
        arch = workflow_job(self.release, "build-image-arch")
        steps = workflow_steps(arch)
        self.assertEqual(condition(steps[1]), "github.event_name != 'pull_request'")
        for name in ("Configure Docker Buildx", "Compute per-architecture tags", "Build release image", "Smoke test release image"):
            step = next(step for step in steps if step.startswith("name: " + name))
            self.assertEqual(condition(step), LOCAL_OR_PUBLISH)
        build = next(step for step in steps if "uses: docker/build-push-action@v7" in step)
        self.assertIn("push: ${{ github.event_name != 'pull_request' }}", build)
        self.assertIn("load: ${{ github.event_name == 'pull_request' }}", build)
        manifest = workflow_job(self.release, "build-image")
        self.assertIn("if: github.event_name != 'pull_request'", manifest.split("steps:")[0])

    def test_stale_architectures_skip_every_post_guard_step_including_smoke(self):
        arch = workflow_job(self.release, "build-image-arch")
        self.assertIn("arch: amd64", arch)
        self.assertIn("arch: arm64", arch)
        for step in workflow_steps(arch)[2:]:
            with self.subTest(step=step.splitlines()[0]):
                self.assertIn(PUBLISH_GATE, condition(step) or "")

    def test_stale_manifest_skips_outputs_and_sign_and_downstream_release(self):
        manifest = workflow_job(self.release, "build-image")
        steps = workflow_steps(manifest)
        for step in steps[2:]:
            with self.subTest(step=step.splitlines()[0]):
                self.assertIn(PUBLISH_GATE, condition(step) or "")
        publish = next(step for step in steps if "id: publish\n" in step)
        self.assertEqual(condition(publish), PUBLISH_GATE)
        self.assertIn('echo "digest=$digest"', publish)
        self.assertIn('echo "tags_text<<EOF"', publish)
        sign = next(step for step in steps if step.startswith("name: Cosign"))
        self.assertIn(PUBLISH_GATE, condition(sign))
        self.assertIn('"$IMAGE@$REGULAR_DIGEST"', sign)
        self.assertIn('"${IMAGE}:${SOURCE_SUFFIX}-amd64"', publish)
        self.assertIn('"${IMAGE}:${SOURCE_SUFFIX}-arm64"', publish)
        self.assertIn("needs.build-image.outputs.digest != ''", workflow_job(self.release, "release"))

    def test_read_only_tests_run_on_any_pr_base_and_join_existing_ci_final_gate(self):
        ci = (ROOT / ".github/workflows/ci.yaml").read_text()
        self.assertIn("  pull_request:\n  push:", ci)
        job = workflow_job(ci, "release-publication-ref")
        self.assertIn("contents: read", job)
        self.assertNotIn(": write", job)
        self.assertIn("persist-credentials: false", job)
        self.assertIn("python3 -m unittest discover -s .github/scripts -p test_check_publish_ref.py -v", job)
        self.assertIn("- release-publication-ref", workflow_job(ci, "tests-done"))


if __name__ == "__main__":
    unittest.main()

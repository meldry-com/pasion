#!/usr/bin/env python3
"""Reject new Clippy diagnostics while keeping the existing backlog visible."""

import argparse
from collections import Counter
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def diagnostics(lines):
    """Count stable source fingerprints, independent of line numbers and targets."""
    # Cargo can emit the same diagnostic for both lib and lib-test. Use the
    # largest multiplicity per target rather than letting target changes hide it.
    targets = {}
    for line in lines:
        record = json.loads(line)
        if record.get("reason") != "compiler-message":
            continue
        message = record["message"]
        if message["level"] not in ("warning", "error"):
            continue
        primary = [span for span in message["spans"] if span["is_primary"]]
        if not primary:
            continue  # rustc's final warning-count summaries are not diagnostics
        key = json.dumps({
            "code": (message.get("code") or {}).get("code"),
            "message": message["message"],
            "source": [
                [span["file_name"].replace("\\", "/"),
                 [text["text"].strip() for text in span["text"]]]
                for span in primary
            ],
        }, sort_keys=True, ensure_ascii=False)
        target = (record.get("target", {}).get("name"),
                  tuple(record.get("target", {}).get("kind", [])))
        targets.setdefault(target, Counter())[key] += 1
    result = Counter()
    for counts in targets.values():
        result |= counts
    return result


def lint(root, output):
    command = ["cargo", "clippy", "--workspace", "--tests", "--bins", "--lib",
               "--locked", "--message-format=json", "--", "--cap-lints", "warn"]
    # The cap allows collecting the entire backlog. The comparison below is the
    # actual gate: new diagnostics, including normally-denied lints, fail it.
    with output.open("w", encoding="utf-8") as stream:
        result = subprocess.run(command, cwd=root, stdout=stream, check=False)
    if result.returncode:
        # Cargo puts compiler diagnostics on JSON stdout, not stderr. Emit
        # them before raising: the caller will remove the temporary checkout
        # and JSON files even when the baseline fails to compile.
        with output.open(encoding="utf-8") as stream:
            for line in stream:
                try:
                    record = json.loads(line)
                except ValueError:
                    print(line.rstrip(), file=sys.stderr)
                    continue
                if record.get("reason") == "compiler-message":
                    message = record["message"]
                    print(message.get("rendered") or message.get("message", ""),
                          file=sys.stderr)
        result.check_returncode()
    with output.open(encoding="utf-8") as stream:
        return diagnostics(stream)


def comparison_base(root, requested, pr_head):
    if pr_head:
        parents = subprocess.check_output(
            ["git", "rev-list", "--parents", "-n", "1", "HEAD"],
            cwd=root, text=True).split()
        # GitHub may build a newer merge preview while the event still names
        # the old base SHA. Only trust the preview's first parent when its
        # second parent is exactly this PR's head, not an author's own merge.
        if len(parents) == 3 and parents[2] == pr_head:
            return parents[1]
    return subprocess.check_output(
        ["git", "rev-parse", "--verify", requested + "^{commit}"],
        cwd=root, text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-ref", required=True)
    parser.add_argument("--pr-head", default="")
    args = parser.parse_args()
    root = Path(subprocess.check_output(
        ["git", "rev-parse", "--show-toplevel"], text=True).strip())
    # The caller supplies an exact commit from the event, never a PR-controlled
    # executable or shell expression. Keep both checkouts on the same toolchain.
    base = comparison_base(root, args.base_ref, args.pr_head)
    with tempfile.TemporaryDirectory(prefix="pasion-clippy-") as directory:
        scratch = Path(directory)
        checkout = scratch / "base"
        subprocess.run(["git", "worktree", "add", "--detach", str(checkout), base],
                       cwd=root, check=True)
        try:
            old = lint(checkout, scratch / "base.jsonl")
            new = lint(root, scratch / "head.jsonl")
        finally:
            # Only remove the detached checkout created in this temporary dir.
            if checkout.resolve().parent != scratch.resolve():
                raise RuntimeError("Refusing to remove checkout outside temporary directory")
            subprocess.run(["git", "worktree", "remove", "--force", str(checkout)],
                           cwd=root, check=True)
    added = new - old
    for diagnostic, count in sorted(added.items()):
        print(f"NEW ({count}): {diagnostic}")
    print(f"Clippy diagnostics: base={sum(old.values())}, head={sum(new.values())}, "
          f"new={sum(added.values())}")
    return bool(added)


if __name__ == "__main__":
    raise SystemExit(main())

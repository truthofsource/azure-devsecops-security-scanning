"""Manual, offline TruffleHog scan of reachable main-branch Git history.

Only aggregate counts reach stdout. Raw scanner streams remain in a private
temporary directory for this process lifetime and are never uploaded.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import hashlib
import time
from datetime import datetime, timezone
import uuid
from pathlib import Path

from trufflehog_report import (MAX_OUTPUT_BYTES, ScanOutputError, load_suppressions,
                              parse_findings, validate_completion)

EXPECTED_REMOTE = "https://github.com/truthofsource/trufflehog-secret-detection.git"
EXPECTED_REMOTES = {EXPECTED_REMOTE, EXPECTED_REMOTE.removesuffix(".git")}
PIN_FILE = Path(__file__).resolve().parents[1] / "security" / "trufflehog-lock.json"
POLICY_FILE = Path(__file__).resolve().parents[1] / "security" / "trufflehog-suppressions.json"
IMAGE_RE = re.compile(r"ghcr\.io/trufflesecurity/trufflehog@sha256:[0-9a-f]{64}")
VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
SHA_RE = re.compile(r"[0-9a-f]{40}")


class ScanError(Exception):
    """Fixed-text public error; scanner stdout and stderr must stay private."""


def bound_output_files() -> None:
    # The manual workflow runs on Linux. Bound Docker CLI writes before the
    # post-scan parser can inspect them; an oversized stream fails the scan.
    import resource
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_OUTPUT_BYTES, MAX_OUTPUT_BYTES))


def stop_container(container: str) -> None:
    try:
        subprocess.run(["docker", "rm", "-f", container], capture_output=True,
                       timeout=15, check=False)
    except (OSError, subprocess.SubprocessError):
        pass


def git_value(repo: Path, *args: str) -> str:
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith("GIT_")}
    environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                       GIT_TERMINAL_PROMPT="0", GIT_NO_REPLACE_OBJECTS="1",
                       GIT_NO_LAZY_FETCH="1")
    try:
        result = subprocess.run(["git", "-c", "core.fsmonitor=false", "-c",
                                 "protocol.allow=never", "-C", str(repo), *args],
                                capture_output=True, timeout=30, check=False, env=environment)
        value = result.stdout.decode("utf-8", errors="strict").strip()
    except (OSError, UnicodeError, subprocess.SubprocessError) as exc:
        raise ScanError("repository preflight failed") from exc
    if result.returncode:
        raise ScanError("repository preflight failed")
    return value


def preflight(repo: Path, expected_head: str | None = None) -> str:
    if not repo.is_dir() or git_value(repo, "rev-parse", "--is-inside-work-tree") != "true":
        raise ScanError("repository preflight failed")
    top = Path(git_value(repo, "rev-parse", "--show-toplevel")).resolve()
    if top != repo.resolve():
        raise ScanError("repository root required")
    # Mount only an isolated complete clone, never a linked developer worktree.
    git_dir = repo / ".git"
    if not git_dir.is_dir() or git_dir.is_symlink():
        raise ScanError("isolated Git directory required")
    if any((git_dir / name).exists() for name in
           ("info/grafts", "objects/info/alternates", "shallow")):
        raise ScanError("incomplete or rewritten Git history")
    config_keys = git_value(repo, "config", "--local", "--name-only", "--list").lower().splitlines()
    allowed_keys = {"core.repositoryformatversion", "core.filemode", "core.bare",
                    "core.logallrefupdates", "core.ignorecase", "core.symlinks",
                    "remote.origin.url", "remote.origin.fetch", "branch.main.remote",
                    "branch.main.merge", "gc.auto", "user.name", "user.email"}
    if any(key not in allowed_keys for key in config_keys):
        raise ScanError("unsupported local Git configuration")
    if git_value(repo, "for-each-ref", "--format=%(refname)", "refs/replace/"):
        raise ScanError("rewritten Git history")
    if git_value(repo, "remote", "get-url", "origin") not in EXPECTED_REMOTES:
        raise ScanError("unexpected repository origin")
    if git_value(repo, "rev-parse", "--is-shallow-repository") != "false":
        raise ScanError("incomplete Git history")
    if git_value(repo, "status", "--porcelain"):
        raise ScanError("clean checkout required")
    head = git_value(repo, "rev-parse", "HEAD")
    if not SHA_RE.fullmatch(head):
        raise ScanError("invalid Git commit")
    if expected_head is not None and (not SHA_RE.fullmatch(expected_head) or head != expected_head):
        raise ScanError("checkout differs from expected commit")
    if git_value(repo, "branch", "--show-current") != "main":
        raise ScanError("main branch required")
    return head


def history_coverage(repo: Path) -> dict:
    # Missing objects must fail, rather than silently reducing scan coverage.
    git_value(repo, "rev-list", "--objects", "--missing=error", "HEAD")
    count = git_value(repo, "rev-list", "--count", "HEAD")
    roots = git_value(repo, "rev-list", "--max-parents=0", "HEAD").splitlines()
    if (not count.isdigit() or not 1 <= int(count) <= 1_000_000
            or not 1 <= len(roots) <= 128 or any(not SHA_RE.fullmatch(root) for root in roots)):
        raise ScanError("invalid history coverage")
    return {"reachable_commit_count": int(count), "root_commit_shas": sorted(roots),
            "excluded_scopes": ["other_refs", "unreachable_objects", "lfs", "submodules",
                                "issues", "artifacts", "sibling_worktrees"]}


def image_pin() -> tuple[str, str]:
    try:
        lock = json.loads(PIN_FILE.read_text(encoding="utf-8"))
        image = lock["image"]
        version = lock["version"]
        if (not isinstance(image, str) or not IMAGE_RE.fullmatch(image)
                or not isinstance(version, str) or not VERSION_RE.fullmatch(version)
                or lock["platform"] != "linux/amd64"):
            raise ValueError
        return image, version
    except (OSError, KeyError, ValueError, TypeError) as exc:
        raise ScanError("invalid scanner lock") from exc


def validate_receipt(receipt: dict) -> None:
    """Validate the public schema independently of scanner/private output."""
    fields = {"schema_version", "mode", "commit", "scanner", "completed", "coverage_complete",
              "started_at_utc", "finished_at_utc", "elapsed_seconds", "policy_sha256",
              "reachable_commit_count", "root_commit_shas", "excluded_scopes",
              "findings", "suppressed", "needs_review"}
    try:
        if set(receipt) != fields or type(receipt["schema_version"]) is not int or receipt["schema_version"] != 2:
            raise ValueError
        if receipt["mode"] != "manual_main_history" or receipt["completed"] is not True or receipt["coverage_complete"] is not True:
            raise ValueError
        if not SHA_RE.fullmatch(receipt["commit"]) or not IMAGE_RE.fullmatch(receipt["scanner"]):
            raise ValueError
        if not re.fullmatch(r"[a-f0-9]{64}", receipt["policy_sha256"]):
            raise ValueError
        for key in ("findings", "suppressed", "needs_review", "reachable_commit_count"):
            if type(receipt[key]) is not int or not 0 <= receipt[key] <= 1_000_000:
                raise ValueError
        if receipt["findings"] != receipt["suppressed"] + receipt["needs_review"] or receipt["reachable_commit_count"] < 1:
            raise ValueError
        roots = receipt["root_commit_shas"]
        if not isinstance(roots, list) or not 1 <= len(roots) <= 128 or any(not isinstance(root, str) or not SHA_RE.fullmatch(root) for root in roots) or roots != sorted(set(roots)):
            raise ValueError
        if receipt["excluded_scopes"] != ["other_refs", "unreachable_objects", "lfs", "submodules", "issues", "artifacts", "sibling_worktrees"]:
            raise ValueError
        start = datetime.fromisoformat(receipt["started_at_utc"])
        finish = datetime.fromisoformat(receipt["finished_at_utc"])
        if start.utcoffset() != timezone.utc.utcoffset(start) or finish.utcoffset() != timezone.utc.utcoffset(finish) or finish < start:
            raise ValueError
        if type(receipt["elapsed_seconds"]) not in (int, float) or not 0 <= receipt["elapsed_seconds"] <= 3600:
            raise ValueError
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        raise ScanError("invalid public scan receipt") from exc


def run_scan(repo: Path, timeout: int = 600, triage_file: Path | None = None,
             expected_head: str | None = None, *, since_commit: str | None = None) -> dict:
    started = datetime.now(timezone.utc).isoformat()
    clock = time.monotonic()
    head = preflight(repo, expected_head)
    coverage = history_coverage(repo)
    if since_commit is not None:
        if not SHA_RE.fullmatch(since_commit) or git_value(repo, "merge-base", since_commit, head) != since_commit:
            raise ScanError("invalid incremental scan boundary")
    if triage_file and (not triage_file.is_absolute() or triage_file.exists()
                        or triage_file.is_symlink()
                        or triage_file.resolve().is_relative_to(repo.resolve())):
        raise ScanError("new private triage path required outside the repository")
    image, version = image_pin()
    policy_digest = hashlib.sha256(POLICY_FILE.read_bytes()).hexdigest()
    suppressions = load_suppressions(POLICY_FILE)
    container = "workforce-trufflehog-" + uuid.uuid4().hex[:16]
    with tempfile.TemporaryDirectory(prefix="workforce-secret-scan-") as temp:
        private = Path(temp)
        if os.name != "nt":
            private.chmod(0o700)
        output = private / "scan.ndjson"
        errors = private / "scan.stderr"
        pull_output = private / "pull.stdout"
        pull_errors = private / "pull.stderr"
        command = [
            "docker", "run", "--rm", "--pull=never", "--name", container,
            "--platform", "linux/amd64", "--network", "none", "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--tmpfs", "/tmp:rw,nosuid,nodev,size=128m",
            "--mount", f"type=bind,src={repo.resolve()},dst=/repo,readonly",
            image, "--no-verification", "--no-update", "--no-filter-unverified",
            "--results=verified,unknown,unverified,filtered_unverified",
            "--json", "--fail", "--fail-on-scan-errors", "git", "file:///repo", "--branch", "HEAD",
        ]
        if since_commit is not None:
            command.extend(["--since-commit", since_commit])
        try:
            with pull_output.open("wb") as stdout, pull_errors.open("wb") as stderr:
                pulled = subprocess.run(["docker", "pull", "--platform", "linux/amd64", image],
                                        stdout=stdout, stderr=stderr, timeout=120, check=False,
                                        preexec_fn=bound_output_files if os.name != "nt" else None)
        except (OSError, subprocess.SubprocessError) as exc:
            raise ScanError("pinned scanner image fetch failed") from exc
        if pulled.returncode:
            raise ScanError("pinned scanner image fetch failed")
        try:
            with output.open("wb") as stdout, errors.open("wb") as stderr:
                status = subprocess.run(command, stdout=stdout, stderr=stderr,
                                        timeout=timeout, check=False,
                                        preexec_fn=bound_output_files if os.name != "nt" else None).returncode
        except subprocess.TimeoutExpired as exc:
            stop_container(container)
            raise ScanError("scan timed out; coverage incomplete") from exc
        except (OSError, subprocess.SubprocessError) as exc:
            stop_container(container)
            raise ScanError("scanner execution failed") from exc
        if status not in (0, 183):
            stop_container(container)
            raise ScanError("scanner reported incomplete coverage")
        validate_completion(errors, version)
        locations: list[tuple[str, str, str, int]] | None = [] if triage_file else None
        counts = parse_findings(output, suppressions, locations)
        if (status == 0 and counts["findings"]) or (status == 183 and not counts["findings"]):
            raise ScanError("scanner status and output disagree")
        # Detect a moved checkout rather than attaching its result to a new head.
        if preflight(repo, head) != head or history_coverage(repo) != coverage:
            raise ScanError("repository changed during scan")
        if hashlib.sha256(POLICY_FILE.read_bytes()).hexdigest() != policy_digest:
            raise ScanError("suppression policy changed during scan")
        if triage_file:
            if not triage_file.is_absolute() or triage_file.resolve().is_relative_to(repo.resolve()):
                raise ScanError("private triage path must be outside the repository")
            try:
                descriptor = os.open(triage_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "w", encoding="utf-8") as destination:
                    json.dump({"schema_version": 1, "commit": head,
                               "locations": [{"detector": d, "commit": c, "path": p, "line": n}
                                             for d, c, p, n in locations]}, destination)
            except OSError as exc:
                raise ScanError("private triage file could not be created") from exc
        receipt = {"schema_version": 2, "mode": "manual_main_history", "commit": head,
                "scanner": image, "completed": True, "coverage_complete": True,
                "started_at_utc": started,
                "finished_at_utc": datetime.now(timezone.utc).isoformat(),
                "elapsed_seconds": round(time.monotonic() - clock, 3),
                "policy_sha256": policy_digest,
                **coverage, **counts}
        validate_receipt(receipt)
        return receipt


def range_boundary(repo: Path, base: str, head: str) -> tuple[str, int]:
    if not all(isinstance(value, str) and SHA_RE.fullmatch(value) for value in (base, head)):
        raise ScanError("exact base and head commits required")
    preflight(repo, head)
    if git_value(repo, "rev-parse", base + "^{commit}") != base:
        raise ScanError("base commit unavailable")
    ancestors = git_value(repo, "merge-base", "--all", base, head).splitlines()
    if len(ancestors) != 1 or not SHA_RE.fullmatch(ancestors[0]):
        raise ScanError("one unambiguous merge base required")
    count = git_value(repo, "rev-list", "--count", head, "^" + ancestors[0])
    if not count.isdigit() or not 1 <= int(count) <= 10000:
        raise ScanError("nonempty bounded pull request history required")
    return ancestors[0], int(count)


def run_pr_scan(repo: Path, base: str, head: str) -> dict:
    ancestor, count = range_boundary(repo, base, head)
    report = run_scan(repo, expected_head=head, since_commit=ancestor)
    validate_receipt(report)
    if range_boundary(repo, base, head) != (ancestor, count):
        raise ScanError("pull request range changed during scan")
    return {**report, "schema_version": 3, "mode": "pull_request_range",
            "base_commit": base, "merge_base": ancestor, "range_commit_count": count,
            "enforced": False, "outcome": "review_needed" if report["needs_review"] else "no_review_candidates"}


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline manual Workforce secret scan")
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--expected-head", required=True, help="Exact reviewed main commit")
    parser.add_argument("--triage-file", type=Path,
                        help="Optional new private file outside the repository with locations only")
    parser.add_argument("--pr-base", help="Separate exact PR-range mode; baseline behavior is unchanged when absent")
    args = parser.parse_args()
    try:
        if args.pr_base:
            if args.triage_file:
                raise ScanError("private PR triage is a separate operation")
            result = run_pr_scan(args.repo, args.pr_base, args.expected_head)
        else:
            result = run_scan(args.repo, triage_file=args.triage_file, expected_head=args.expected_head)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ScanError, ScanOutputError) as exc:
        print(json.dumps({"schema_version": 2, "completed": False, "coverage_complete": False,
                          "error": str(exc)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

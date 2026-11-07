"""Checkov Terraform baseline foundation: findings advisory, execution errors fatal."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def expected_version():
    lines = (ROOT / "security/checkov-requirements.in").read_text().splitlines()
    pins = [line.removeprefix("checkov==") for line in lines if line.startswith("checkov==")]
    if len(pins) != 1 or not all(part.isdigit() for part in pins[0].split(".")):
        raise ValueError("One exact Checkov version pin is required")
    return pins[0]


def stage_terraform(source, destination):
    paths = subprocess.check_output(["git", "ls-files", "-z"], cwd=source).decode().split("\0")
    manifest = {}
    for name in paths:
        path = Path(name)
        if not name or path.parts[0] != "infra" or not name.endswith((".tf", ".tf.json")):
            continue
        original = source / path
        if (".." in path.parts or original.is_symlink()
                or not original.resolve().is_relative_to(source.resolve()) or not original.is_file()):
            raise ValueError("Terraform input must be a regular file inside the checkout")
        payload = original.read_bytes()
        target = destination / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
        manifest[path.as_posix()] = hashlib.sha256(payload).hexdigest()
    if not manifest:
        raise ValueError("No tracked Terraform inputs; baseline is incomplete")
    return manifest


def validate_report(report, version):
    # One framework requested; reject unexpected additional reports/frameworks.
    if isinstance(report, list) and len(report) == 1:
        report = report[0]
    if not isinstance(report, dict) or report.get("check_type") != "terraform":
        raise ValueError("Expected a single Terraform report")
    summary, results = report.get("summary"), report.get("results")
    if not isinstance(summary, dict) or not isinstance(results, dict):
        raise ValueError("Missing Checkov summary/results")
    if summary.get("checkov_version") != version:
        raise ValueError("Checkov report version differs from the pin")
    for name in ("passed", "failed", "skipped", "parsing_errors", "resource_count"):
        if type(summary.get(name)) is not int or summary[name] < 0:
            raise ValueError("Invalid Checkov counts")
    for name in ("passed", "failed", "skipped"):
        rows = results.get(name + "_checks")
        if not isinstance(rows, list) or len(rows) != summary[name]:
            raise ValueError("Checkov counts do not match evidence")
        for row in rows:
            if not isinstance(row, dict) or not all(
                    isinstance(row.get(key), str) and row[key].strip()
                    for key in ("check_id", "resource", "file_path")):
                raise ValueError("Malformed Checkov finding")
    if results.get("parsing_errors") != [] or summary["parsing_errors"]:
        raise ValueError("Terraform parsing errors; baseline is incomplete")
    if not summary["resource_count"] or not summary["passed"] + summary["failed"]:
        raise ValueError("No evaluated checks/resources; baseline is incomplete")
    return summary


def scanner_environment(temp):
    # No Azure/Graph/Prisma credentials or CKV environment overrides are needed.
    allowed = {"PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "LANG", "LC_ALL"}
    env = {k: v for k, v in os.environ.items() if k.upper() in allowed}
    env.update(HOME=str(temp), USERPROFILE=str(temp), TMP=str(temp), TEMP=str(temp),
               TMPDIR=str(temp), PYTHONUTF8="1", PYTHONNOUSERSITE="1")
    return env


def run(executable, source, output, module=False):
    executable, source, output = executable.resolve(), source.resolve(), output.resolve()
    if output.exists() and any(output.iterdir()):
        raise ValueError("Use an empty output directory; stale evidence is not accepted")
    output.mkdir(parents=True, exist_ok=True)
    version = expected_version()
    # Windows pip exposes a checkov script plus a .cmd shim that requires a
    # system .py association. Invoke that exact script through the venv Python.
    command = [str(executable), str(executable.parent / "checkov")] if module else [str(executable)]
    with tempfile.TemporaryDirectory(prefix="workforce-checkov-") as directory:
        temp = Path(directory)
        environment = scanner_environment(temp)
        actual = subprocess.check_output([*command, "--version"], cwd=temp,
                                         env=environment, text=True, timeout=60).strip()
        if actual != version:
            raise ValueError("Checkov executable differs from the pin")
        staged = temp / "source"
        manifest = stage_terraform(source, staged)
        config = temp / "checkov.yaml"
        config.write_text("{}\n", encoding="utf-8")
        arguments = [*command, "--directory", str(staged / "infra"),
                     "--framework", "terraform", "--config-file", str(config),
                     "--download-external-modules", "false", "--skip-download",
                     "--skip-results-upload", "--soft-fail", "--output", "json"]
        with (output / "checkov.json").open("w", encoding="utf-8") as report, \
                (output / "stderr.log").open("w", encoding="utf-8") as errors:
            result = subprocess.run(arguments, cwd=temp, env=environment,
                                    stdout=report, stderr=errors, timeout=1200)
        if result.returncode != 0:
            raise RuntimeError("Checkov execution failed; report-only is not error suppression")
        data = json.loads((output / "checkov.json").read_text(encoding="utf-8"))
        summary = validate_report(data, version)
        receipt = {"mode": "advisory-baseline", "securityGate": False,
                   "scanner": "checkov", "version": version, "counts": summary,
                   "sourceSha": subprocess.check_output(
                       ["git", "rev-parse", "HEAD"], cwd=source, text=True).strip(),
                   "workingTreeChanges": bool(subprocess.check_output(
                       ["git", "status", "--porcelain", "--untracked-files=no"], cwd=source)),
                   "inputs": manifest, "reportSha256": hashlib.sha256(
                       (output / "checkov.json").read_bytes()).hexdigest(),
                   "completedAtUtc": datetime.now(timezone.utc).isoformat()}
        (output / "scan.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        text = (f"Checkov baseline complete; NOT a release security gate.\n"
                f"Failed checks: {summary['failed']}; skipped checks: {summary['skipped']}.\n"
                "Review failures, inline skips and module coverage before enforcement.\n")
        (output / "summary.txt").write_text(text, encoding="utf-8")
        print(text)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkov", required=True, type=Path)
    parser.add_argument("--module", action="store_true",
                        help="Use --checkov as a Python interpreter and run its adjacent checkov script")
    parser.add_argument("--source", type=Path, default=ROOT)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    run(args.checkov, args.source, args.output, args.module)

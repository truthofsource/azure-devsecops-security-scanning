"""Select App CI work from a complete local Git diff; uncertainty runs all jobs."""
import json
import os
from pathlib import Path
import re
import subprocess

JOBS = ("api", "web", "sql", "importer", "directory")
SHA = re.compile(r"[0-9a-f]{40}")
TRUFFLEHOG_ONLY = {
    ".github/workflows/trufflehog-manual-baseline.yml",
    ".github/workflows/trufflehog-contract-ci.yml",
    "scripts/trufflehog_scan.py",
    "scripts/trufflehog_pr.py",
    "scripts/test_trufflehog_pr.py",
    ".github/workflows/trufflehog-pr.yml",
    "scripts/trufflehog_report.py",
    "scripts/test_trufflehog_scan.py",
    "security/trufflehog-lock.json",
    "security/trufflehog-suppressions.json",
}


def classify(paths):
    selected = set()
    if not paths:
        return dict.fromkeys(JOBS, True)
    for path in paths:
        parts = path.split("/")
        if (not path or path.startswith("/") or "\\" in path
                or any(p in ("", ".", "..") for p in parts)
                or any(ord(c) < 32 for c in path)):
            return dict.fromkeys(JOBS, True)
        # Instruction files can affect implementation and must never suppress CI.
        if parts[-1] in ("AGENTS.md", "SKILL.md"):
            return dict.fromkeys(JOBS, True)
        if path == "docs/documentation-inventory.csv" or (path.startswith("docs/") and path.endswith(".md")) or parts[-1] == "README.md":
            continue
        # This isolated scanner has its own small synthetic contract workflow.
        # Exact paths keep new or unfamiliar security files on the full suite.
        if path in TRUFFLEHOG_ONLY:
            continue
        if path.startswith("apps/web/"):
            selected.add("web")
            # SQL integration compares the UI and API catalogs byte-for-structure.
            if path == "apps/web/src/lib/employeeProfileFields.json":
                selected.update(("api", "sql"))
            # API unit tests read the public import sample and task catalog.
            elif path in ("apps/web/public/bulk-applications-example.json",
                          "apps/web/src/lib/workforceTaskCatalog.ts"):
                selected.add("api")
        elif path.startswith("apps/api/test-integration/"):
            # Integration fixtures use the SQL job, which compiles API code.
            selected.add("sql")
        elif path.startswith("apps/api/src/") and path.endswith(".test.ts"):
            selected.add("api")
            # The web import contract test evaluates this API fixture directly.
            if path == "apps/api/src/employmentApplications/bulkApplicationCsv.test.ts":
                selected.add("web")
        elif path.startswith("apps/api/"):
            # SQL exercises API queries; web imports API parsers and their
            # transitive dependencies; the directory artifact packages API JS.
            # Keep all three consumers until dependency selection is automated.
            selected.update(("api", "web", "sql", "directory"))
        elif path.startswith("apps/provider-importer/"):
            selected.add("importer")
        elif path.startswith("apps/directory-worker/"):
            selected.update(("api", "directory"))
        else:
            # Database, workflows, scripts, shared/config files, new components
            # and unfamiliar paths retain the entire suite.
            return dict.fromkeys(JOBS, True)
    return {job: job in selected for job in JOBS}


def git(*args, cwd=None):
    return subprocess.run(["git", *args], cwd=cwd, check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=30).stdout


def changed_paths(event_name, event, source, cwd=None):
    if not isinstance(source, str) or not SHA.fullmatch(source):
        raise ValueError("Invalid source")
    if git("rev-parse", "HEAD", cwd=cwd).decode().strip() != source:
        raise ValueError("Checkout does not match event source")
    if event_name == "pull_request":
        base = event["pull_request"]["base"]["sha"]
    elif event_name == "push":
        base = event["before"]
    else:
        raise ValueError("Unsupported event")
    if not isinstance(base, str) or not SHA.fullmatch(base) or base == "0" * 40:
        raise ValueError("Invalid base")
    if event_name == "pull_request":
        base = git("merge-base", base, source, cwd=cwd).decode().strip()
    # No rename collapsing: both the old and new paths must influence selection.
    data = git("diff", "--name-only", "--no-renames", "-z", base, source, "--", cwd=cwd)
    if data and not data.endswith(b"\0"):
        raise ValueError("Incomplete diff")
    return data.decode("utf-8").split("\0")[:-1] if data else []


def plan(event_name, event, source, cwd=None):
    try:
        return classify(changed_paths(event_name, event, source, cwd)), "complete-diff"
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError):
        return dict.fromkeys(JOBS, True), "full-suite-fallback"


def main():
    try:
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
    except (KeyError, ValueError, OSError):
        event = {}
    selection, reason = plan(os.environ.get("GITHUB_EVENT_NAME"), event,
                             os.environ.get("GITHUB_SHA"))
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        for job, required in selection.items():
            output.write(f"{job}={str(required).lower()}\n")
    # Do not emit filenames, event payloads or Git error details.
    print(json.dumps({"reason": reason, "jobs": selection}, sort_keys=True))


if __name__ == "__main__":
    main()

"""Pinned Trivy scans; no Azure authentication, installs from package manifests or provider calls."""
import argparse
from collections import Counter
from datetime import date, datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def install(destination):
    spec = json.loads((ROOT / "security/scanners.json").read_text())["trivy"]
    system = platform.system().lower()
    machine = platform.machine().lower()
    if system not in ("linux", "windows") or not (
            machine in ("amd64", "x86_64") or (system == "windows" and machine == "arm64")):
        raise ValueError("Installer requires x86-64 or Windows ARM64 with x64 emulation")
    item = spec[system]
    url = f"https://github.com/aquasecurity/trivy/releases/download/v{spec['version']}/{item['archive']}"
    with urllib.request.urlopen(url, timeout=120) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != item["sha256"]:
        raise ValueError("Scanner download checksum mismatch; nothing executed")
    name = "trivy.exe" if system == "windows" else "trivy"
    # Extract only the executable, never archive-controlled paths or links.
    if system == "windows":
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            executable = archive.read(name)
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            member = archive.getmember(name)
            if not member.isfile():
                raise ValueError("Scanner executable is not a regular file")
            executable = archive.extractfile(member).read()
    destination.mkdir(parents=True, exist_ok=True)
    target = destination / name
    target.write_bytes(executable)
    target.chmod(0o755)
    print(f"Verified Trivy {spec['version']}: {target}")


def scan_input(path):
    parts = path.parts
    if not parts or parts[0] not in ("apps", "infra", "scripts", "platform"):
        return False
    return (path.name in ("package.json", "package-lock.json", "yarn.lock", "requirements.txt", "Dockerfile")
            or path.name.endswith((".tf", ".tf.json", ".Dockerfile")))


def stage_source(source, destination):
    """Only tracked scanner inputs; never local evidence, .terraform, state, or credentials."""
    paths = subprocess.check_output(["git", "ls-files", "-z"], cwd=source).decode().split("\0")
    selected = []
    for value in paths:
        path = Path(value)
        if not value or not scan_input(path):
            continue
        original = source / path
        if original.is_symlink() or not original.resolve().is_relative_to(source.resolve()):
            raise ValueError("Scan input must be a regular file within the checkout")
        target = destination / path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original, target)
        selected.append(path.as_posix())
    if not any(p.endswith("package-lock.json") for p in selected):
        raise ValueError("No tracked dependency lockfiles to scan")
    return selected


def validate_report(path, kind):
    report = json.loads(path.read_text(encoding="utf-8"))
    if report.get("SchemaVersion") != 2 or not isinstance(report.get("Results"), list):
        raise ValueError("Missing or unsupported Trivy results; scan is not clean")
    results = report["Results"]
    if kind == "vuln" and not any(r.get("Packages") for r in results):
        raise ValueError("No package inventory; vulnerability scan is not complete")
    if kind == "misconfig" and not any(r.get("MisconfSummary") for r in results):
        raise ValueError("No configuration checks evaluated")
    return report


def gate_findings(report, kind):
    """Evaluate saved complete results, never confuse a CLI error with a CVE exit code."""
    selected = []
    key = "Vulnerabilities" if kind == "vuln" else "Misconfigurations"
    for result in report["Results"]:
        findings = result.get(key) or []
        if not isinstance(findings, list):
            raise ValueError("Malformed finding list")
        for finding in findings:
            if not isinstance(finding, dict) or finding.get("Severity") not in (
                    "UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
                raise ValueError("Missing or invalid finding severity")
            if finding["Severity"] not in ("HIGH", "CRITICAL"):
                continue
            if kind == "vuln" and not finding.get("FixedVersion"):
                continue
            if kind == "misconfig":
                if finding.get("Status") not in ("FAIL", "PASS", "EXCEPTION"):
                    raise ValueError("Unknown misconfiguration status")
                if finding["Status"] != "FAIL":
                    continue
            selected.append({"target": result.get("Target"), "id": finding.get("VulnerabilityID", finding.get("ID")),
                             "severity": finding["Severity"], "package": finding.get("PkgName"),
                             "installed": finding.get("InstalledVersion"), "fixed": finding.get("FixedVersion"),
                             "resource": (finding.get("CauseMetadata") or {}).get("Resource")})
    return selected


def apply_exceptions(findings, exceptions, scope, today=None):
    today = today or datetime.now(timezone.utc).date()
    fields = ("target", "id", "package", "installed", "resource")
    if not isinstance(exceptions, list):
        raise ValueError("Exceptions must be a list")
    for item in exceptions:
        if not isinstance(item, dict) or not all(k in item for k in (*fields, "scope", "owner", "reason", "expires")):
            raise ValueError("Exception requires exact scope, finding, owner, reason and expiration")
        if not all(isinstance(item[k], str) and item[k].strip() for k in ("scope", "target", "id", "owner", "reason")):
            raise ValueError("Exception justification and exact scope cannot be blank")
        if date.fromisoformat(item["expires"]) <= today:
            raise ValueError("Expired exception requires review; it cannot suppress a finding")
    blocked, accepted = [], []
    for finding in findings:
        matches = [e for e in exceptions if e["scope"] == scope and all(e[k] == finding[k] for k in fields)]
        (accepted if matches else blocked).append(finding)
    return blocked, accepted


def classify_existing_iac(findings, baseline, today=None):
    """Keep exact pre-existing IaC results visible and block new occurrences."""
    today = today or datetime.now(timezone.utc).date()
    required = {"schemaVersion", "owner", "expiresUtc", "reason", "findings"}
    if not isinstance(baseline, dict) or set(baseline) != required or baseline["schemaVersion"] != 1:
        raise ValueError("Invalid Terraform finding baseline")
    if not all(isinstance(baseline[k], str) and baseline[k].strip()
               for k in ("owner", "expiresUtc", "reason")):
        raise ValueError("Terraform baseline needs owner, reason and expiration")
    if date.fromisoformat(baseline["expiresUtc"]) <= today:
        raise ValueError("Terraform finding baseline expired; review existing findings")
    entries = baseline["findings"]
    if not isinstance(entries, list) or not entries:
        raise ValueError("Terraform finding baseline cannot be empty")
    keys = ("id", "target", "resource")
    for item in entries:
        if (not isinstance(item, dict) or set(item) != set(keys)
                or not all(isinstance(item[k], str) and item[k].strip() for k in keys)):
            raise ValueError("Terraform baseline entries need exact ID, target and resource")
    remaining = Counter(tuple(item[k] for k in keys) for item in entries)
    new, existing = [], []
    for finding in findings:
        signature = tuple(finding.get(k) for k in keys)
        if remaining[signature] > 0:
            remaining[signature] -= 1
            existing.append(finding)
        else:
            new.append(finding)
    return new, existing


def vulnerability_scan_arguments(mode, common, report, target):
    # --include-dev-deps is an fs-only flag in the pinned Trivy CLI.
    dev_dependencies = ["--include-dev-deps"] if mode == "fs" else []
    return [mode, *common, "--scanners", "vuln", *dev_dependencies,
            "--list-all-pkgs", "--format", "json", "--output", str(report), target]


def scan(executable, source, output, image=None, dependencies_only=False, report_only=False):
    executable = str(executable.resolve())
    output = output.resolve()
    if output.exists() and any(output.iterdir()):
        raise ValueError("Use an empty report directory to prevent stale evidence")
    output.mkdir(parents=True, exist_ok=True)
    environment = {k: v for k, v in os.environ.items() if not k.startswith("TRIVY_")}
    with tempfile.TemporaryDirectory(prefix="workforce-security-") as folder:
        temp = Path(folder)
        docker_config = temp / "public-registry-config"
        docker_config.mkdir()
        (docker_config / "config.json").write_text('{"auths":{}}', encoding="utf-8")
        environment["DOCKER_CONFIG"] = str(docker_config)
        (temp / "config.yaml").write_text("{}\n")
        (temp / "ignore").write_text("")
        common = ["--config", str(temp / "config.yaml"), "--ignorefile", str(temp / "ignore"),
                  "--cache-dir", str(temp / "cache"), "--timeout", "15m", "--disable-telemetry", "--quiet"]

        def run(arguments):
            result = subprocess.run([executable, *arguments], cwd=temp, env=environment, timeout=1200)
            if result.returncode:
                raise RuntimeError("Trivy failed; missing evidence must not pass")
            return result.returncode

        version = subprocess.check_output([executable, "--version"], env=environment, text=True).strip()
        expected = json.loads((ROOT / "security/scanners.json").read_text())["trivy"]["version"]
        if f"Version: {expected}" not in version.splitlines():
            raise ValueError("Scanner version differs from the reviewed pin")
        metadata = {"scanner": version, "startedAtUtc": datetime.now(timezone.utc).isoformat(),
                    "policy": "HIGH/CRITICAL fixable CVEs; new HIGH/CRITICAL misconfigurations; exact dated exceptions and expiring existing-IaC baseline"}
        if image:
            # Resolve a local Docker image once and scan its immutable ID, not a mutable tag.
            identity = json.loads(subprocess.check_output(["docker", "image", "inspect", image], text=True))[0]
            target = identity["Id"]
            metadata.update(imageId=target, repoDigests=identity.get("RepoDigests", []))
            mode = "image"
        else:
            staged = temp / "source"
            staged.mkdir()
            metadata["inputs"] = stage_source(source, staged)
            metadata["sourceSha"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
            metadata["workingTreeChanges"] = bool(subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=source))
            target = str(staged)
            mode = "fs"
        report = output / "vulnerabilities.json"
        # Record every severity and unfixed issue. The later gate only blocks fixable HIGH/CRITICAL.
        run(vulnerability_scan_arguments(mode, common, report, target))
        vulnerability_data = validate_report(report, "vuln")
        if not image:
            expected_locks, empty_locks = set(), []
            for path in metadata["inputs"]:
                if not path.endswith("package-lock.json"):
                    continue
                lock = json.loads((source / path).read_text(encoding="utf-8"))
                packages = lock.get("packages")
                root = packages.get("") if isinstance(packages, dict) else None
                empty = (lock.get("lockfileVersion") in (2, 3) and isinstance(root, dict)
                         and set(packages) == {""} and not lock.get("dependencies")
                         and not any(root.get(key) for key in ("dependencies", "devDependencies", "optionalDependencies")))
                if empty:
                    empty_locks.append(path)
                else:
                    expected_locks.add(path)
            metadata["emptyDependencyLockfiles"] = empty_locks
            reported = {r.get("Target", "").replace("\\", "/") for r in vulnerability_data["Results"]}
            if not expected_locks.issubset(reported):
                raise ValueError("A tracked npm lockfile is missing from scan results")
        for fmt, name in (("cyclonedx", "sbom.cyclonedx.json"), ("spdx-json", "sbom.spdx.json")):
            run(["convert", "--format", fmt, "--output", str(output / name), str(report)])
        findings = gate_findings(vulnerability_data, "vuln")
        existing_iac = []
        if not image and not dependencies_only:
            config = output / "misconfigurations.json"
            run(["config", *common, "--misconfig-scanners", "terraform,dockerfile",
                 "--tf-exclude-downloaded-modules", "--include-non-failures", "--format", "json",
                 "--output", str(config), target])
            iac = gate_findings(validate_report(config, "misconfig"), "misconfig")
            baseline_path = ROOT / "security/terraform-existing-findings.json"
            iac_baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
            if report_only and date.fromisoformat(iac_baseline["expiresUtc"]) <= datetime.now(timezone.utc).date():
                # Expired findings are visible and unaccepted; never extend their expiry automatically.
                new_iac, existing_iac = iac, []
                metadata["iacBaselineExpired"] = True
            else:
                new_iac, existing_iac = classify_existing_iac(iac, iac_baseline)
            findings.extend(new_iac)
            metadata["iacBaselineSha256"] = hashlib.sha256(baseline_path.read_bytes()).hexdigest()
            metadata["iacBaselineExpiresUtc"] = iac_baseline["expiresUtc"]
        exceptions = json.loads((ROOT / "security/exceptions.json").read_text(encoding="utf-8"))
        findings, accepted = apply_exceptions(findings, exceptions, target if image else "source")
        blocked = bool(findings)
        metadata["mode"] = "report-only" if report_only else "enforced"
        metadata["needsReview"] = blocked
        (output / "blocking-findings.json").write_text(json.dumps(findings, indent=2) + "\n", encoding="utf-8")
        (output / "accepted-findings.json").write_text(json.dumps(accepted, indent=2) + "\n", encoding="utf-8")
        (output / "advisory-existing-iac.json").write_text(json.dumps(existing_iac, indent=2) + "\n", encoding="utf-8")
        summary = (f"Security scan: {'BLOCKED' if blocked else 'PASS'}\n"
                   f"Blocking findings: {len(findings)}\n"
                   f"Existing Terraform findings awaiting review: {len(existing_iac)}\n")
        (output / "summary.txt").write_text(summary, encoding="utf-8")
        metadata.update(blocked=blocked, acceptedFindings=len(accepted),
                        advisoryExistingIac=len(existing_iac),
                        exceptionPolicySha256=hashlib.sha256((ROOT / "security/exceptions.json").read_bytes()).hexdigest(),
                        completedAtUtc=datetime.now(timezone.utc).isoformat())
        (output / "scan.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
        print("Security findings require review" if blocked else "Security thresholds passed")
        return int(blocked and not report_only)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    setup = commands.add_parser("install")
    setup.add_argument("--directory", type=Path, required=True)
    check = commands.add_parser("scan")
    check.add_argument("--trivy", type=Path, required=True)
    check.add_argument("--source", type=Path, default=ROOT)
    check.add_argument("--output", type=Path, required=True)
    check.add_argument("--image")
    check.add_argument("--dependencies-only", action="store_true")
    check.add_argument("--report-only", action="store_true", help="Report findings without suppressing execution or coverage failures")
    args = parser.parse_args()
    if args.command == "install":
        install(args.directory)
        return 0
    return scan(args.trivy, args.source.resolve(), args.output, args.image, args.dependencies_only, args.report_only)


if __name__ == "__main__":
    raise SystemExit(main())

"""Parse private TruffleHog NDJSON into an aggregate, non-sensitive report."""

from __future__ import annotations

import json
import re
from datetime import date, datetime, timezone
from pathlib import Path

MAX_OUTPUT_BYTES = 32 * 1024 * 1024
MAX_DIAGNOSTIC_BYTES = 4 * 1024 * 1024
MAX_RECORDS = 100_000
COMMIT = re.compile(r"[0-9a-f]{40}")
DETECTOR = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,79}")


class ScanOutputError(Exception):
    """Safe, fixed-text error; never include source content."""


def validate_completion(path: Path, expected_version: str) -> None:
    """Require the pinned scanner's one-source completion record."""
    try:
        if path.stat().st_size > MAX_DIAGNOSTIC_BYTES:
            raise ScanOutputError("scan diagnostics exceeded limit")
        lines = path.read_bytes().splitlines()
    except OSError as exc:
        raise ScanOutputError("scan diagnostics unavailable") from exc
    finished = 0
    for line in lines:
        # Docker may add a plain-text runtime notice to stderr. The scanner's
        # structured completion record, version, coverage and exit code still
        # have to agree; never treat an unstructured line as completion.
        if not line.lstrip().startswith(b"{"):
            continue
        try:
            record = json.loads(line)
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise ScanOutputError("malformed scan diagnostics") from exc
        if not isinstance(record, dict) or not isinstance(record.get("msg"), str):
            raise ScanOutputError("malformed scan diagnostics")
        if str(record.get("level", "")).startswith("error"):
            raise ScanOutputError("scanner reported an error")
        if record["msg"] == "finished scanning":
            finished += 1
            if (record.get("trufflehog_version") != expected_version
                    or type(record.get("chunks")) is not int or record["chunks"] < 1
                    or type(record.get("bytes")) is not int or record["bytes"] < 1):
                raise ScanOutputError("scan completion metadata invalid")
    if finished != 1:
        raise ScanOutputError("scan completion unconfirmed")


def _location(record: dict) -> tuple[str, str, str, int]:
    try:
        git = record["SourceMetadata"]["Data"]["Git"]
        detector = record["DetectorName"]
        commit = git["commit"]
        path = git["file"]
        line = git["line"]
    except (KeyError, TypeError) as exc:
        raise ScanOutputError("unsupported finding metadata") from exc
    if not isinstance(detector, str) or not DETECTOR.fullmatch(detector):
        raise ScanOutputError("invalid detector metadata")
    if not isinstance(commit, str) or not COMMIT.fullmatch(commit):
        raise ScanOutputError("invalid commit metadata")
    if not isinstance(path, str) or not path or path.startswith("/") or "\\" in path or "\x00" in path:
        raise ScanOutputError("invalid path metadata")
    if any(part in ("", ".", "..") for part in path.split("/")):
        raise ScanOutputError("invalid path metadata")
    if type(line) is not int or line < 1:
        raise ScanOutputError("invalid line metadata")
    return detector, commit, path, line


def load_suppressions(path: Path, today: date | None = None) -> set[tuple[str, str, str, int]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ScanOutputError("invalid suppression policy") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != 1 or not isinstance(payload.get("suppressions"), list):
        raise ScanOutputError("invalid suppression policy")
    today = today or datetime.now(timezone.utc).date()
    active: set[tuple[str, str, str, int]] = set()
    for item in payload["suppressions"]:
        if not isinstance(item, dict) or set(item) != {"detector", "commit", "path", "line", "owner", "reason", "expires"}:
            raise ScanOutputError("invalid suppression policy")
        if not all(isinstance(item[k], str) and item[k].strip() for k in ("owner", "reason")):
            raise ScanOutputError("invalid suppression policy")
        try:
            expiry = date.fromisoformat(item["expires"])
        except (TypeError, ValueError) as exc:
            raise ScanOutputError("invalid suppression policy") from exc
        key = _location({"DetectorName": item["detector"], "SourceMetadata": {"Data": {"Git": {"commit": item["commit"], "file": item["path"], "line": item["line"]}}}})
        if key in active:
            raise ScanOutputError("duplicate suppression")
        if expiry >= today:
            active.add(key)
    return active


def parse_findings(path: Path, suppressions: set[tuple[str, str, str, int]],
                   triage: list[tuple[str, str, str, int]] | None = None) -> dict[str, int]:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ScanOutputError("scan output unavailable") from exc
    if size > MAX_OUTPUT_BYTES:
        raise ScanOutputError("scan output exceeded limit")
    count = 0
    locations: dict[tuple[str, str, str, int], int] = {}
    records: list[tuple[str, str, str, int]] = []
    with path.open("rb") as source:
        for line in source:
            if not line.strip():
                continue
            count += 1
            if count > MAX_RECORDS or len(line) > MAX_OUTPUT_BYTES:
                raise ScanOutputError("scan output exceeded limit")
            try:
                record = json.loads(line)
            except (ValueError, UnicodeError, RecursionError) as exc:
                raise ScanOutputError("malformed scan output") from exc
            if not isinstance(record, dict):
                raise ScanOutputError("malformed scan output")
            location = _location(record)
            locations[location] = locations.get(location, 0) + 1
            if triage is not None:
                records.append(location)
    # A second finding at the same immutable commit/line must re-enter review.
    suppressed = sum(1 for key in suppressions if locations.get(key) == 1)
    if triage is not None:
        triage.extend(key for key in records if key not in suppressions or locations[key] != 1)
    return {"findings": count, "suppressed": suppressed, "needs_review": count - suppressed}

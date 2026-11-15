# Troubleshooting lessons from the actual platform

These are historical engineering incidents summarized from maintained internal records. They are not newly reproduced tests, a fresh cloud inventory or instructions to repeat a consumed operation. Names, resource identifiers, private payloads and credentials are excluded.

## An empty result was missing coverage, not finding nothing

**What happened.** A Trivy command could finish without the expected operating-system package results.

**What the evidence showed.** The pinned Ubuntu inventory path needed lsb-release as well as the package database. Staging only os-release did not establish the expected coverage. An empty report was therefore insufficient evidence of a clean target.

**What changed and how it was checked.** The validation path required the distribution metadata and a nonempty expected OS-package inventory. Failed or incomplete reports stayed visible rather than being converted into zero-vulnerability success.

**What to carry forward.** Prove what the scanner examined before interpreting its findings count. Preserve the exact target, tool/database evidence, expected inventory and completion status; this specific metadata repair is not a universal explanation for every empty report.

Source record: `docs/troubleshooting/vulnerability-scanning.md — November 4 compatibility and host-inventory lessons`. These internal paths identify provenance; they are not public file links.

## Docker worked, but emulated workloads crashed

**What happened.** The workstation could run its Linux engine, while x64 browser or SQL workloads failed under emulation.

**What the evidence showed.** The host engine was ARM64. Recorded Chromium QEMU failures and a SQL Server signal-11 failure concerned emulated workloads; they did not establish that Docker was absent, the engine was unreachable or the application would fail on native x64.

**What changed and how it was checked.** The process kept the failed receipts and used the existing native x64 validation path where that runtime was required. ACR native builds retained their verification stage; a classic builder rejecting RUN --network=none was handled with an explicit BuildKit task, not by removing the network restriction.

**What to carry forward.** Check CLI installation, engine reachability, architecture and workload compatibility independently. Publishing an earlier runtime stage or passing a different-architecture test does not prove the final intended image ran its browser or SQL checks.

Source record: `docs/troubleshooting/profile-photos-and-security-scans.md — Local SQL crashes while Docker works; docs/troubleshooting/vulnerability-scanning.md — November 5 continuation`. These internal paths identify provenance; they are not public file links.

## Evidence and project boundaries

The local examples and screenshots in this repository remain separate from the dated hosted incidents above. A new documentation summary does not establish another successful deployment, restore, security scan or business transaction. Follow the repository’s existing validation guide for the commands and limits of the runnable reference.

The practical sequence is: identify the failing boundary, preserve safe correlation evidence, reconcile any uncertain result, apply only the relevant repair and verify the resulting state. A completed local command is not interchangeable with a completed cloud operation.

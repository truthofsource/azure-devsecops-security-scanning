> This example is maintained within **azure-devsecops-security-scanning**. Run its local commands from this subfolder; its nested workflow files are retained examples and are not active repository workflows. See [the consolidation guide](https://github.com/truthofsource/azure-devsecops-security-scanning/blob/main/docs/CONSOLIDATION.md).

# Trivy Vulnerability and Container Scanning

**See what software a release contains, what weaknesses were found and whether the check finished.**

[Business problem](#the-business-problem) · [Strengths](#where-trivy-is-strong) · [Proof](#proof-it-works) · [Commands](docs/COMMANDS.md) · [Step by step](#step-by-step)

## The Business Problem

The application and its background workers depend on software maintained by other teams, including Node.js packages, Linux components and browser libraries. An engineer may update the application while an older vulnerable package remains inside the worker image, or review an image while missing a dependency used during the build.

The release decision needs more than a list of warnings. Staff need to know which exact package or image was checked, whether the scan completed, which findings have compatible fixes and which remain unresolved. A report for another image can create false confidence, while an untested package upgrade can break the service being protected.

The business problem was to make software risk actionable and traceable to the release under review, with fixes tested for compatibility and remaining issues kept visible.

## The Solution

Use a verified version of Trivy to inspect selected source files and container images. Keep all findings, create software inventories, and apply a separate release rule for High or Critical issues with an available fix. Keep software and infrastructure findings separate.

**Business outcome:** Recorded compatible package updates removed seven reported occurrences. The source scan still showed 21 Medium and one Low occurrence, so it was not described as a completely clean release.

## Tools Used and What They Do

| Tool or service | What it does | Where it fits |
| --- | --- | --- |
| Trivy | Inspect software packages and container-image contents for known weaknesses. | Actual scanner; a completed command still needs expected inventory coverage. |
| Docker and Azure Container Registry | Provide the selected image and its immutable digest. | Target/build infrastructure; the scanned digest must match the release candidate. |
| SBOM output | Record the software inventory associated with the selected scan. | Evidence document, not a separate scanner or proof of zero vulnerabilities. |
| Python and GitHub Actions | Test report/policy behavior with fictional inputs. | Public validation is local/manual-only, not a fresh image scan. |

This retained tool project remains linked from the combined security-scanning portfolio entry. Historical scanner results keep their original target, date and coverage limits.

## Step by Step

Your own Trivy scan of a Terraform file you create, followed by a documented fix and rescan.

[Open the standalone build guide](docs/BUILD-YOUR-OWN.md) or follow the same complete instructions below.

Start with a new folder, your own files and your own accounts. The numbered steps below describe the build; no portfolio repository checkout is required. The existing implementation/evidence elsewhere in this repository is a separate reference, not a claim that your new build has already passed.

### Prerequisites

Your editor and Trivy prerequisites; a fresh lab folder. This source-only scan needs no Azure deployment or credentials; do not apply the deliberately weak fixture. The dependency exercise also needs Node/npm; its deliberately old package is scan input only and must not be deployed.

Use Bash on Linux/macOS/WSL for Bash blocks and PowerShell for PowerShell blocks. Select the tool versions supported by the official sources below, record the versions you actually install and retain generated dependency locks. Cloud resources, scanner downloads, logs and external AI calls can create costs; review the stated scope before enabling them.

### Create your project folder

Choose a new folder name. These first commands create a blank project; an optional `git init` gives it its own history. Create parent directories in your editor when a later step introduces a nested file.

```bash
mkdir my-trivy-vulnerability-management
cd my-trivy-vulnerability-management
git init
```

Create `.gitignore` before saving credentials or build outputs:

```gitignore
.venv/
node_modules/
.env
.env.*
local.settings.json
credentials.json
token.json
*.pem
*.key
*.tfstate*
*.tfplan
.terraform/
private*/
captures/
backups/
batch.json
reports/
out/
app-config.local.yaml
```

The source/file snippets are a starting implementation you type or paste into the named files. Replace `YOUR_*`, names, regions and addresses only with values from your own lab; do not place real client/employee records in a test project. Keep your terminal in this project root unless a step explicitly changes directory.

Before a first commit, set your own repository-local author with `git config user.name "YOUR_NAME"` and `git config user.email "YOUR_PUBLIC_COMMIT_EMAIL"`. Review `git status --short` and the staged diff before publishing; ignored local files are not a substitute for reviewing what you upload.

### Step 1 — Choose the control and record the tool

**Where:** Your workstation.

Install Trivy using its official instructions for your operating system. Record trivy --version; its vulnerability scan needs a downloaded database, so a database/download failure must not be called a clean scan.

```bash
trivy --version
```

**Check before continuing:** The tool version is recorded and its prerequisite check succeeds.

### Step 2 — Create your test infrastructure file

**Where:** A new infra folder.

Create infra/main.tf below, intentionally with a weak TLS setting so you can investigate one concrete control. It is a scanner input, not an approved deployment configuration.

Create **`infra/main.tf`** with the following contents:

```hcl
resource "azurerm_storage_account" "lab" {
  name                     = "myuniquelabstorage"
  resource_group_name      = "rg-my-scanner-lab"
  location                 = "eastus2"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_0"
}
```

**Check before continuing:** You have authored the file that the scanner will inspect.

### Step 3 — Run and retain the first scan

**Where:** Your project root.

Create a reports folder and run the command below. Retain the original output and exit status so a later successful scan does not erase what you found.

```bash
mkdir -p reports
trivy config --format json --output reports/trivy.json infra
```

**Check before continuing:** A parseable report exists; an empty or failed scan is not passed off as success.

### Step 4 — Read the finding in context

**Where:** The JSON report and infra/main.tf.

Find the storage/TLS finding, note the rule identifier and target, then change TLS1_0 to TLS1_2 and rerun. Other findings may remain; compare the same target/rule instead of assuming the entire report is clean.

**Check before continuing:** Your before/after record identifies the exact setting you corrected.

### Step 5 — Create and scan a dependency example

**Where:** A new app directory in your project.

Create a package with the intentionally old Express version below, retain the first vulnerability report, then select a reviewed fixed version, install it exactly and rescan. Keep the old package off any running/public service; scan results depend on the tool/database and must be inspected rather than predeclared.

```bash
mkdir app
cd app
npm init -y
npm install --save-exact express@4.17.1
cd ..
trivy fs --scanners vuln --format json --output reports/packages-before.json app
# Select/review an appropriate fixed version, then replace the placeholder:
npm install --prefix app --save-exact express@YOUR_REVIEWED_FIXED_VERSION
trivy fs --scanners vuln --format json --output reports/packages-after.json app
```

**Check before continuing:** You have a dependency finding/fix comparison, or a documented actual result if the database differs.

### Step 6 — Prove the changed result

**Where:** Your terminal.

Save a second report under a different filename and compare rule/resource outcomes with the first. Record unresolved findings with an owner and next action rather than deleting scanner rules or claiming scan success means the design is secure.

**Check before continuing:** The TLS correction is observable, and other risks remain visible.

### Step 7 — Add your own repeatable check

**Where:** Your own GitHub repository, optionally.

Create a manual workflow that installs your reviewed tool version, scans this file and retains safe reports. Keep credentials/private reports out of artifacts and use no Azure deployment permission for a source-only scan.

**Check before continuing:** A reader can reproduce the same input, tool version, finding and fix without your portfolio repository.

### Verification and your own screenshots

| Evidence | What to record | Your result |
| --- | --- | --- |
| New build | Your own files/resource settings and tool versions | Not yet recorded |
| Working path | The actual successful request, configuration or recovery result | Not yet recorded |
| Failure boundary | A meaningful denied, malformed, stale or failed case | Not yet recorded |
| Recovery / cleanup | What you restored or removed and what remains billed | Not yet recorded |

Capture your own architecture/configuration, one working result and one failure/recovery result. Keep tokens, credentials, personal records and private identifiers out of public screenshots. The architecture diagram explains the design; record your own results rather than treating it as execution evidence.

### Troubleshooting order

1. Confirm the named file, working directory and selected tool/interpreter.
2. Check the exact input and resource/account selected for the failing step.
3. Separate identity permission, network/DNS reachability and application validation.
4. Keep the actual error and reconcile an unknown write outcome before repeating it; do not widen access or repeat paid operations blindly.

The numbered steps describe a build procedure. Local syntax checks, an accepted API request, a completed hosted operation and a human verification are different evidence levels; fill in the verification table with what you actually observed.

### Official implementation references

- [trivy.dev — docs](https://trivy.dev/latest/docs/)

<details>
<summary>Reference: how the existing platform implementation operates</summary>

A short walkthrough of the process, with technical instructions and evidence limits in the sections below.

1. **Choose the software to inspect** — Select the application files or container image for the review. Record the exact version so the results can be traced back to it.

2. **Run the selected scan (Trivy)** — Trivy checks supported software packages for known security weaknesses. It can also create a list of the software included in the release.

3. **Review fixes and release rules** — Keep the full findings report and identify available updates. The selected release rule treats fixable High or Critical findings separately from other results.

4. **Test the update and scan again** — Check that the chosen update still works with the application. Preserve the new results and any remaining findings rather than describing an incomplete review as clean.

</details>

## Where Trivy Is Strong

| Strength | Practical value |
| --- | --- |
| **Package and image visibility** | Check supported operating-system and application packages inside a container, plus the recorded package versions in source code. These checks cover different parts of a release. |
| **Reusable inventory** | Create software lists in the standard CycloneDX and SPDX JSON formats. These lists, called SBOMs, help compare releases and check packages again later. |
| **Repeatable release evidence** | Record the scanner version, the checked files and the exact release. Confirm that the scan finished before applying the release rules. |

This tool covers one part of security. The other scanners check different areas, so the results need to be considered together. [Strengths, limits and tradeoffs](docs/STRENGTHS-AND-TRADEOFFS.md).

## Architecture

1. **Selected source / image / Git history** → **Validate scope and identity**.
2. **Pinned trusted scanner and policy** → **Run selected scan**.
3. **Validate scope and identity** → **Run selected scan**.
4. **Run selected scan** → **Private or controlled raw evidence**.
5. **Private or controlled raw evidence** → **Validate coverage / version / completion**.
6. **Validate coverage / version / completion** → **Separate findings from execution errors**.
7. **Separate findings from execution errors** → **Review / repair / retest / preserve receipt**.

[View the illustrated project overview](../../docs/diagrams/architecture.svg).

Each scanner checks a different kind of information and needs suitable protection for its reports. Trivy 0.75.0 is the selected source pin, not a claim that it is the latest release. [Actual source map](docs/SOURCE-MAP.md).

## What Was Built

| Component | Purpose | Implementation |
| --- | --- | --- |
| Scan script | Check the intended files with trusted tools and protect the report | [Source](scripts/security_scan.py) |
| Existing behavior tests | Reject missing or unreadable reports and checks of the wrong files | [Tests](scripts/) |
| Fixed scanner version and settings | Record the tool version and the rules used | [Configuration](security/) |
| Real pipeline example | Show how the real pipeline runs checks, without running it here | [Inert workflow](reference/workflows/security-release.yml.example) |
| Platform findings | Preserve dated fixes and remaining work | [Recorded findings](data/platform-findings.json) |
| Offline example/viewer | Exercise actual parsing/decision code with fictional inputs | [Example](scripts/demo.py) |

## Proof It Works

### 1. Test the actual boundary code

```bash
python -B -m unittest discover -s scripts -p 'test_*.py' -v
python -B scripts/demo.py
```

**Look for:** 12 original tests. The demonstration using test data is labeled and does not pretend to be a current full-platform scan. [Dated validation](docs/VALIDATION.md) records exact executed/skipped cases.

### 2. Inspect genuine scanner evidence separately

A real local scan of the public API lockfile inventoried six packages and reported zero vulnerabilities against the existing local database. Configuration fixtures were scanned separately, and both CycloneDX and SPDX JSON were generated. The test-only gate demonstration intentionally blocks one fixable High finding while retaining all three raw fixture findings.

Local scans cover only this public reference. Dated platform reports are retained as history; local test-example output does not replace or clear the full platform finding register. No cloud credentials, resource changes or provider credential verification are needed.

### 3. Follow findings through to a defensible decision

Keep the target, version, database/policy context and completion evidence. Review the actual finding, apply a compatible fix where justified, repeat the relevant checks and preserve unresolved items. A scanner timeout, incorrectly structured report or missing inventory cannot become a successful scan with zero findings.

### Recorded compatible fixes

| Dependency | Selected repair | Why it matters |
| --- | --- | --- |
| Backstage catalog backend | 4.0.0 → 4.0.2 | Repair the affected catalog-location validation path |
| fast-uri | 3.1.8 → 3.1.9 | Address URI scheme/host/path advisories without forcing a new major |
| qs | Compatible 6.x ranges → 6.16.2 | Repair hostile query-array serialization while preserving newer instances |
| postcss-selector-parser | Affected 6.x/7.x lines → their compatible patch | Avoid breaking consumers by imposing one major on every parent |

The dated source evidence went from 26 Medium/three Low to 21 Medium/one Low occurrences. The seven removed occurrences and exact advisory identifiers are in [the platform finding record](data/platform-findings.json). Remaining infrastructure findings and expired-baseline state are separate from dependency thresholds. These are recorded source repairs, not a new scan or deployment of every live image.

## Run the Local Viewer

```bash
python -B scripts/preview.py --port 8138
```

Open [the local reference](http://127.0.0.1:8138). It shows strengths, actual parser behavior on fictional input and dated platform evidence. It performs no scan, cloud request or sign-in. Ctrl+C stops it. Screenshots are local captures, not a hosted security dashboard.

## Limitations and Tradeoffs

| Boundary | What it means |
| --- | --- |
| Coverage follows target | Checking source files is different from checking the released container. A package finding does not by itself prove the application can be attacked. |
| Database age matters | The local reference used an existing DB without updating it; no vulnerability result is timeless. |
| Threshold is policy | Unfixed and Medium findings remain visible even when a fixable High/Critical threshold does not block. |

The reference workflow is manual-only. Actual platform integration examples are inert files outside .github/workflows. No hosted CI run or deployment was performed to create this project. Do not execute candidate package scripts or expose raw secret candidates while adding security checks.

## Troubleshooting Lessons

An apparently empty scan lacked the expected Ubuntu package coverage. The repair checked required distribution metadata and inventory before interpreting the vulnerability count. [Read the incident, evidence and verification](docs/LESSONS-LEARNED.md).

## Project Guides

| Guide | Purpose |
| --- | --- |
| [Strengths and tradeoffs](docs/STRENGTHS-AND-TRADEOFFS.md) | Why this scanner, where it helps and where it stops |
| [Process and integration](docs/PROCESS.md) | Scope, trust, completion and CI decisions |
| [Findings and fixes](docs/FINDINGS-AND-FIXES.md) | Recorded results versus local examples |
| [Commands](docs/COMMANDS.md) | Commands to repeat the local checks and start the scanner |
| [Operations](docs/OPERATIONS.md) | Handle failures, protect private data and prioritize findings |
| [Scaling](docs/SCALING.md) | Choose what to scan and manage time, cost and access |
| [Source map](docs/SOURCE-MAP.md) | Where the code came from and what changed for this example |
| [Validation](docs/VALIDATION.md) | Local test results and their limits |

Related projects: [Trivy](https://github.com/truthofsource/azure-devsecops-security-scanning/tree/main/tools/trivy), [TruffleHog](https://github.com/truthofsource/azure-devsecops-security-scanning/tree/main/tools/trufflehog), [Checkov](https://github.com/truthofsource/azure-devsecops-security-scanning/tree/main/tools/checkov), and [delivery/rollback](https://github.com/truthofsource/azure-container-lifecycle/tree/main/examples/signed-container-delivery).

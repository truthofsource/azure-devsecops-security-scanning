> This example is maintained within **azure-devsecops-security-scanning**. Run its local commands from this subfolder; its nested workflow files are retained examples and are not active repository workflows. See [the consolidation guide](https://github.com/truthofsource/azure-devsecops-security-scanning/blob/main/docs/CONSOLIDATION.md).

# Authenticated Web and API Security with OWASP ZAP

**Check what users can reach after sign-in, including what lower-access accounts must be denied.**

[Business problem](#the-business-problem) · [Solution](#the-solution) · [Strengths](#engineering-strengths) · [Proof](#proof-it-works) · [Commands](docs/COMMANDS.md) · [Step by step](#step-by-step)

## The Business Problem

Different people use the same platform for different work: caregivers submit their records, while HR and administrators review protected employee information. A scan that reaches only the public sign-in page cannot show whether those boundaries still hold after a user signs in.

A page that hides a staff button may still leave its server route reachable by another role. Testing that behavior against sensitive records or using write actions can create operational risk, and saved access tokens or private responses can make a security report sensitive in its own right.

The business need was a controlled way to observe selected signed-in requests, confirm expected access and denials and retain useful findings without exposing employee information or changing business records.

## The Solution

Use OWASP ZAP to inspect a small, fixed set of read-only web requests. Confirm the signed-in accounts and roles, compare the expected allowed and denied responses, and report only safe summary information. This test observes traffic without sending active attack requests.

**Business outcome:** The recorded test covered ten read-only requests across four server handlers. It found two informational cache observations and no Low, Medium or High alerts in that limited sample; it did not clear the whole application.

## Tools Used and What They Do

| Tool or service | What it does | Where it fits |
| --- | --- | --- |
| OWASP ZAP | Observe the selected web/API requests for runtime security issues. | Actual DAST tool; passive, active and authenticated modes have different scopes. |
| Playwright and Chromium | Prepare/check browser sessions and protected viewer behavior. | Platform acceptance tooling; the local viewer does not sign into Entra. |
| Microsoft Entra ID | Supply the Admin and Caregiver identities compared in access checks. | Actual authentication boundary; no credentials or reusable sessions are included. |
| Python and GitHub Actions | Exercise the bounded request/report contract with fictional responses. | Public validation is local/manual-only, not a live authenticated scan. |

This retained tool project remains linked from the combined security-scanning portfolio entry. Historical scanner results keep their original target, date and coverage limits.

## Step by Step

Your own local web target, a passive ZAP baseline report and an authenticated-testing design with explicit limits.

[Open the standalone build guide](docs/BUILD-YOUR-OWN.md) or follow the same complete instructions below.

Start with a new folder, your own files and your own accounts. The numbered steps below describe the build; no portfolio repository checkout is required. The existing implementation/evidence elsewhere in this repository is a separate reference, not a claim that your new build has already passed.

### Prerequisites

Docker with Linux containers, a reviewed ZAP image, and Python. The target below belongs to you; do not substitute someone else's website without authorization.

Use Bash on Linux/macOS/WSL for Bash blocks and PowerShell for PowerShell blocks. Select the tool versions supported by the official sources below, record the versions you actually install and retain generated dependency locks. Cloud resources, scanner downloads, logs and external AI calls can create costs; review the stated scope before enabling them.

### Create your project folder

Choose a new folder name. These first commands create a blank project; an optional `git init` gives it its own history. Create parent directories in your editor when a later step introduces a nested file.

```bash
mkdir my-owasp-zap-authenticated-security
cd my-owasp-zap-authenticated-security
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

### Step 1 — Create your local target

**Where:** A new site directory.

Create site/index.html with a harmless page. It is intentionally small so you can identify exactly what ZAP has and has not seen.

Create **`site/index.html`** with the following contents:

```html
<!doctype html><html lang="en"><head><meta charset="utf-8"><title>My ZAP lab</title></head><body><h1>My test site</h1><a href="/">Home</a></body></html>
```

**Check before continuing:** Your own HTML file exists.

### Step 2 — Create an isolated Docker network and serve the page

**Where:** Your terminal.

Create a lab network and run an official Python image serving only the site directory. Keep the container on that network; the ZAP container can use the site container name instead of exposing a public target.

```bash
docker network create my-zap-lab
docker run -d --name my-zap-site --network my-zap-lab   -v "$PWD/site:/site:ro" -w /site python:3.12-slim   python -m http.server 8000 --bind 0.0.0.0
```

**Check before continuing:** The target container is running and the network belongs only to your lab.

### Step 3 — Run a passive baseline

**Where:** The same project folder.

Create a reports directory writable by the selected scanner container user, select a reviewed ZAP image tag/digest and run the baseline below. Baseline crawling and passive analysis are different from an active attack scan; preserve the exit code and report.

```bash
mkdir -p reports
# Replace this placeholder with your reviewed ZAP image reference.
export ZAP_IMAGE="ghcr.io/zaproxy/zaproxy:YOUR_REVIEWED_TAG"
docker run --rm --network my-zap-lab -v "$PWD/reports:/zap/wrk:rw"   "$ZAP_IMAGE" zap-baseline.py -t http://my-zap-site:8000 -r baseline.html
```

**Check before continuing:** Your local site is inspected and an HTML report is generated.

### Step 4 — Investigate and fix a finding

**Where:** The report and your web-server configuration.

To investigate missing response headers, create the server below and restart your own local target with it. Generate a second baseline report under a new name and compare the applicable header findings; do not claim this fixes unrelated alerts.

Create **`site/server.py`** with the following contents:

```python
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
class Handler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        self.send_header('X-Content-Type-Options', 'nosniff')
        super().end_headers()
ThreadingHTTPServer(('0.0.0.0', 8000), Handler).serve_forever()
```

```bash
docker rm -f my-zap-site
docker run -d --name my-zap-site --network my-zap-lab   -v "$PWD/site:/site:ro" -w /site python:3.12-slim python server.py
docker run --rm --network my-zap-lab -v "$PWD/reports:/zap/wrk:rw"   "$ZAP_IMAGE" zap-baseline.py -t http://my-zap-site:8000 -r after-headers.html
```

**Check before continuing:** Your before/after record shows one tested correction or a reasoned, owned limitation.

### Step 5 — Plan authenticated coverage correctly

**Where:** Your own application, when it has sign-in.

Configure a ZAP context, authentication method, user/session handling, included URLs and reliable logged-in/logged-out indicators for that app. Supply two distinct test roles and a request allowlist; verify role responses independently because a passive scan cannot prove authorization or business logic.

**Check before continuing:** You have a reproducible sign-in/session test design, not a claim that the anonymous sample tested Entra roles.

### Step 6 — Capture evidence and remove the lab

**Where:** Your terminal.

Keep a report summary, target/network diagram and the exact image reference. Stop/remove my-zap-site and remove my-zap-lab; retain no real session tokens in reports or public screenshots.

```bash
docker rm -f my-zap-site
docker network rm my-zap-lab
```

**Check before continuing:** The lab target and network are gone and your evidence states the passive scope.

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

- [www.zaproxy.org — baseline-scan](https://www.zaproxy.org/docs/docker/baseline-scan/)
- [www.zaproxy.org — authentication](https://www.zaproxy.org/docs/desktop/start/features/authentication/)

The walkthrough layout follows the prerequisites → creation/configuration → test → verification → troubleshooting → cleanup pattern of the [Splunk project reference](https://github.com/davidharris6/splunk-siem-log-analysis). Its Splunk-specific settings are not copied into unrelated projects.

<details>
<summary>Reference: how the existing platform implementation operates</summary>

A short walkthrough of the process, with technical instructions and evidence limits in the sections below.

1. **Prepare the approved test accounts (Entra test identities)** — Use authorized users with different access levels for the selected test. Keep their sign-in information and private responses out of public reports.

2. **Send the selected requests (OWASP ZAP)** — The test sends a fixed set of read-only website and server requests through ZAP. This setup observes the traffic without sending active attack requests.

3. **Compare allowed and denied access** — Check whether each account receives the expected response. A lower-access user must not gain permission merely because the page is reachable.

4. **Review the limited results** — Save safe summary information and investigate unexpected behavior. The recorded sample does not establish security coverage for every page or action.

</details>

## Engineering Strengths

| Strength | Practical value |
| --- | --- |
| **HTTP behavior** | Check how the website and server actually respond, including details that software-package and infrastructure scans cannot see. |
| **Authenticated coverage** | Check selected pages or server actions after sign-in, then compare allowed users with users who should be denied. |
| **Controlled passive testing** | Inspect selected web traffic without sending attack requests. Check the expected permissions and publish only safe summaries. |

## Architecture

1. **Fresh authorized sign-in** → **Private short-lived tokens**.
2. **Private short-lived tokens** → **Fixed ten-GET matrix**.
3. **Fixed ten-GET matrix** → **Pinned passive ZAP proxy**.
4. **Pinned passive ZAP proxy** → **Reviewed API handlers**.
5. **Reviewed API handlers** → **Identity / role / expected status**.
6. **Pinned passive ZAP proxy** → **Alert IDs / risk / counts only**.

[View the illustrated project overview](../../docs/diagrams/architecture.svg).

This project is derived from actual workforce-platform implementation. Identifying labels/targets use examples. The local viewer and demonstration are new reference code; [source mapping](docs/SOURCE-MAP.md) identifies the copied/extracted files and limitations.

## What Was Built

| Component | Purpose | Implementation |
| --- | --- | --- |
| Actual authenticated adapter | Fixed target, private token handling and alert-summary filtering | [Source](scripts/zap_authenticated.py) |
| Actual role matrix | Four allowlisted handlers and expected actor/status observations | [Source](scripts/zap_role_matrix.py) |
| Pinned ZAP image | A scanner build identified by its exact fingerprint | [Pin](security/zap-lock.json) |
| Actual tests | Reject wrong identity, incorrectly structured roles, arbitrary routes and token/report leakage | [Tests](scripts/) |
| Local demonstration | Exercise actual rule/evaluation code using fictional data | [Demo](scripts/demo.py) |
| Dated context | Keep earlier platform results separate from the new local example | [Context](data/history.json) |

## Proof It Works

### 1. Run focused checks

```bash
python -B -m unittest discover -s scripts -p 'test_*.py' -v
python -B scripts/demo.py
```

**Observed:** Nine original Python tests of the agreed input and output rules passed. The fictional probe exercises the actual ten-request evaluator. [Validation](docs/VALIDATION.md) records the exact scope and distinguishes pure/mock checks from testing with the hosted services.

### 2. Inspect the decision output

The output is explicitly fictional and exercises the included logic. A successful rule test or simulation is not a completed real-world operation. No new hosted scan, token collection or Microsoft sign-in was performed. The public target is deliberately api.workforce.invalid.

### 3. Open the reference viewer

```bash
python -B scripts/preview.py --port 8139
```

Open [the local reference](http://127.0.0.1:8139). Switch between Overview, Working example and Implementation context. Ctrl+C stops it. Proper application and Azure screenshots are deferred; this remains a runnable local reference.

## Passive, Active and Authenticated

Passive scanning inspects the traffic sent through ZAP. Active scanning generates attack requests and requires a separately authorized target/scope. Authentication changes which paths can be reached; it does not make every scan authenticated or give ZAP permission to test business writes.

The implemented adapter sends only a fixed set of GETs, with no spider, active scan or Microsoft-login replay. It verifies two distinct approved identities and a Caregiver-only role set before protected probes. A second Admin account cannot prove Caregiver denial. Request status assertions are code-defined checks; ZAP alert counts are separate passive observations.

The invalid query/person probes are deliberately expected to return specific Admin error statuses after authorization (400/503), while anonymous and Caregiver calls must be denied (401/403). Those Admin errors are not proof of a successful business operation. This sample does not retrieve real business records or validate every PDF/route.

[ZAP authentication documentation](https://www.zaproxy.org/docs/desktop/start/features/authentication/) describes broader authentication options. The selected platform mode uses privately supplied short-lived tokens rather than automating passwords/MFA.

## Operations, Limits and Growth

State clearly which system is being checked, who owns it and what the result actually proves. Test the cases that should be denied or rejected as well as the successful ones. Keep incomplete results clearly marked. Preserve private inputs and unrelated changes. Before expanding the design, measure what is slow or limited, review costs, and check access restrictions and recovery again. [Operations and scaling](docs/OPERATIONS-AND-SCALING.md).

## Troubleshooting Lessons

A PDF helper failure did not necessarily mean the viewer or authorization was broken. The observation code needed correction while the protected-access checks stayed in place. [Read the incident, evidence and verification](docs/LESSONS-LEARNED.md).

## Project Guides

| Guide | Purpose |
| --- | --- |
| [Implementation](docs/IMPLEMENTATION.md) | Rules, boundaries and actual source design |
| [Commands](docs/COMMANDS.md) | Local tests, expected output and inspection |
| [Operations and scaling](docs/OPERATIONS-AND-SCALING.md) | Strengths, weaknesses, costs and growth |
| [Source map](docs/SOURCE-MAP.md) | Actual files and public adaptations |
| [Validation](docs/VALIDATION.md) | What was tested locally and what still needs real-service testing |

No Azure service, business record or live state was changed. The public validation workflow is manual-only and was not dispatched, conserving hosted Actions minutes.

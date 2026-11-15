# Build your own from scratch: Owasp Zap Authenticated Security

Your own local web target, a passive ZAP baseline report and an authenticated-testing design with explicit limits.

Start with a new folder, your own files and your own accounts. The numbered steps below describe the build; no portfolio repository checkout is required. The existing implementation/evidence elsewhere in this repository is a separate reference, not a claim that your new build has already passed.

## Prerequisites

Docker with Linux containers, a reviewed ZAP image, and Python. The target below belongs to you; do not substitute someone else's website without authorization.

Use Bash on Linux/macOS/WSL for Bash blocks and PowerShell for PowerShell blocks. Select the tool versions supported by the official sources below, record the versions you actually install and retain generated dependency locks. Cloud resources, scanner downloads, logs and external AI calls can create costs; review the stated scope before enabling them.

## Create your project folder

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

## Step 1 — Create your local target

**Where:** A new site directory.

Create site/index.html with a harmless page. It is intentionally small so you can identify exactly what ZAP has and has not seen.

Create **`site/index.html`** with the following contents:

```html
<!doctype html><html lang="en"><head><meta charset="utf-8"><title>My ZAP lab</title></head><body><h1>My test site</h1><a href="/">Home</a></body></html>
```

**Check before continuing:** Your own HTML file exists.

## Step 2 — Create an isolated Docker network and serve the page

**Where:** Your terminal.

Create a lab network and run an official Python image serving only the site directory. Keep the container on that network; the ZAP container can use the site container name instead of exposing a public target.

```bash
docker network create my-zap-lab
docker run -d --name my-zap-site --network my-zap-lab   -v "$PWD/site:/site:ro" -w /site python:3.12-slim   python -m http.server 8000 --bind 0.0.0.0
```

**Check before continuing:** The target container is running and the network belongs only to your lab.

## Step 3 — Run a passive baseline

**Where:** The same project folder.

Create a reports directory writable by the selected scanner container user, select a reviewed ZAP image tag/digest and run the baseline below. Baseline crawling and passive analysis are different from an active attack scan; preserve the exit code and report.

```bash
mkdir -p reports
# Replace this placeholder with your reviewed ZAP image reference.
export ZAP_IMAGE="ghcr.io/zaproxy/zaproxy:YOUR_REVIEWED_TAG"
docker run --rm --network my-zap-lab -v "$PWD/reports:/zap/wrk:rw"   "$ZAP_IMAGE" zap-baseline.py -t http://my-zap-site:8000 -r baseline.html
```

**Check before continuing:** Your local site is inspected and an HTML report is generated.

## Step 4 — Investigate and fix a finding

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

## Step 5 — Plan authenticated coverage correctly

**Where:** Your own application, when it has sign-in.

Configure a ZAP context, authentication method, user/session handling, included URLs and reliable logged-in/logged-out indicators for that app. Supply two distinct test roles and a request allowlist; verify role responses independently because a passive scan cannot prove authorization or business logic.

**Check before continuing:** You have a reproducible sign-in/session test design, not a claim that the anonymous sample tested Entra roles.

## Step 6 — Capture evidence and remove the lab

**Where:** Your terminal.

Keep a report summary, target/network diagram and the exact image reference. Stop/remove my-zap-site and remove my-zap-lab; retain no real session tokens in reports or public screenshots.

```bash
docker rm -f my-zap-site
docker network rm my-zap-lab
```

**Check before continuing:** The lab target and network are gone and your evidence states the passive scope.

## Verification and your own screenshots

| Evidence | What to record | Your result |
| --- | --- | --- |
| New build | Your own files/resource settings and tool versions | Not yet recorded |
| Working path | The actual successful request, configuration or recovery result | Not yet recorded |
| Failure boundary | A meaningful denied, malformed, stale or failed case | Not yet recorded |
| Recovery / cleanup | What you restored or removed and what remains billed | Not yet recorded |

Capture your own architecture/configuration, one working result and one failure/recovery result. Keep tokens, credentials, personal records and private identifiers out of public screenshots. Existing portfolio images are references, not evidence that you performed these steps.

## Troubleshooting order

1. Confirm the named file, working directory and selected tool/interpreter.
2. Check the exact input and resource/account selected for the failing step.
3. Separate identity permission, network/DNS reachability and application validation.
4. Keep the actual error and reconcile an unknown write outcome before repeating it; do not widen access or repeat paid operations blindly.

The numbered steps describe a build procedure. Local syntax checks, an accepted API request, a completed hosted operation and a human verification are different evidence levels; fill in the verification table with what you actually observed.

## Official implementation references

- [www.zaproxy.org — baseline-scan](https://www.zaproxy.org/docs/docker/baseline-scan/)
- [www.zaproxy.org — authentication](https://www.zaproxy.org/docs/desktop/start/features/authentication/)

The walkthrough layout follows the prerequisites → creation/configuration → test → verification → troubleshooting → cleanup pattern of the [Splunk project reference](https://github.com/davidharris6/splunk-siem-log-analysis). Its Splunk-specific settings are not copied into unrelated projects.

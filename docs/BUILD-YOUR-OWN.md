# Build your own from scratch: Azure Devsecops Security Scanning

Your own four-layer security check: secrets, infrastructure settings, package/image vulnerabilities and a running-web baseline.

Start with a new folder, your own files and your own accounts. The numbered steps below describe the build; no portfolio repository checkout is required. The existing implementation/evidence elsewhere in this repository is a separate reference, not a claim that your new build has already passed.

## Prerequisites

A new repository, Python, Git, Docker, Terraform and separately installed/reviewed Trivy, Checkov, TruffleHog and ZAP versions. No Azure credential is needed for the source/local web checks.

Use Bash on Linux/macOS/WSL for Bash blocks and PowerShell for PowerShell blocks. Select the tool versions supported by the official sources below, record the versions you actually install and retain generated dependency locks. Cloud resources, scanner downloads, logs and external AI calls can create costs; review the stated scope before enabling them.

## Create your project folder

Choose a new folder name. These first commands create a blank project; an optional `git init` gives it its own history. Create parent directories in your editor when a later step introduces a nested file.

```bash
mkdir my-azure-devsecops-security-scanning
cd my-azure-devsecops-security-scanning
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

## Step 1 — Define what each tool owns

**Where:** A coverage.md file.

Map TruffleHog to secret candidates, Checkov to IaC settings, Trivy to dependencies/images and ZAP to the running web surface. Define severity/exception ownership and make tool failure a separate outcome from findings.

**Check before continuing:** You have four complementary inputs and no claim that one scanner proves complete security.

## Step 2 — Author your infrastructure fixture

**Where:** Your new infra directory.

Create infra/main.tf below. Scan this deliberate weakness without deploying it; later replace the weak TLS setting and compare findings.

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

**Check before continuing:** The configuration is your own source input.

## Step 3 — Create your application and dependency input

**Where:** Your new app directory.

Create app/server.mjs and app/Dockerfile below. This small local service has no package dependencies; a source scan can correctly report none, while the image still has its own OS/runtime packages to inspect. Create the accompanying .dockerignore before building: .gitignore does not restrict the Docker context, and only the listed runtime files are allowed into this example's context.

Create **`app/server.mjs`** with the following contents:

```javascript
import http from 'node:http';
const server = http.createServer(async (req, res) => {
  const send = (status, value) => {
    res.writeHead(status, {'content-type': 'application/json'});
    res.end(JSON.stringify(value));
  };
  if (req.method === 'GET' && req.url === '/') {
    res.writeHead(200, {'content-type': 'text/html; charset=utf-8'});
    return res.end('<!doctype html><html lang="en"><title>My scanner lab</title><h1>My scanner lab</h1><a href="/api/health">Health</a></html>');
  }
  if (req.method === 'GET' && req.url === '/api/health')
    return send(200, {service: 'my-api', status: 'ok'});
  if (req.method === 'POST' && req.url === '/api/applications') {
    if ((req.headers['content-type'] || '').split(';')[0].trim().toLowerCase() !== 'application/json')
      return send(415, {error: 'Use Content-Type: application/json'});
    let chunks = [], bytes = 0, tooLarge = false;
    try {
      for await (const chunk of req) {
        bytes += chunk.length;
        if (bytes > 4096) { tooLarge = true; chunks = []; }
        else if (!tooLarge) chunks.push(chunk);
      }
    } catch {
      if (req.aborted || res.destroyed || res.writableEnded) return;
      return send(400, {error: 'Request body could not be read; check the connection'});
    }
    if (tooLarge) return send(413, {error: 'Request too large'});
    const raw = Buffer.concat(chunks).toString('utf8');
    let body;
    try { body = JSON.parse(raw); }
    catch { return send(400, {error: 'Send valid JSON'}); }
    if (typeof body?.name !== 'string' || !body.name.trim() ||
        body.name.length > 100 || typeof body?.email !== 'string' ||
        body.email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(body.email))
      return send(422, {error: 'A name and valid email are required'});
    return send(202, {status: 'validated-not-saved'});
  }
  if (req.url === '/api/timesheets')
    return send(401, {error: 'Configure and validate staff authentication before enabling this route'});
  return send(404, {error: 'Route not found'});
});
server.requestTimeout = 10000;
server.headersTimeout = 5000;
server.listen(8080, '0.0.0.0');
```

Create **`app/Dockerfile`** with the following contents:

```dockerfile
FROM node:22-bookworm-slim
WORKDIR /app
COPY server.mjs ./
USER node
CMD ["node", "server.mjs"]
```

Create **`app/.dockerignore`** with the following contents:

```dockerignore
**
!Dockerfile
!server.mjs
```

**Check before continuing:** You can identify what source/package/image each result belongs to.

## Step 4 — Run the three source/history controls

**Where:** Your project root.

Run the commands below with your installed versions and keep their exit codes and private raw reports. Findings can produce nonzero statuses; do not use blanket success overrides or upload secret-bearing raw output.

```bash
mkdir -p reports
trufflehog git "file://$PWD" --no-verification --json > ../private-secret-findings.json
checkov --directory infra --framework terraform --output json > reports/checkov.json
trivy fs --scanners vuln --format json --output reports/trivy-source.json app
```

**Check before continuing:** Each tool has an explicit completed/failed result and owned findings.

## Step 5 — Scan a built image and owned web target

**Where:** Your local Docker environment.

Build your own app image and run a Trivy image scan of its exact selected image. Run ZAP baseline against only your local/authorized app using a lab network and retained report, following the separate tool's official invocation. Confirm GET / returns the lab HTML and /api/health returns JSON before running ZAP; a container merely being Running is not an application readiness test.

```bash
docker build -t my-scanned-web:lab app
trivy image --format json --output reports/trivy-image.json my-scanned-web:lab
docker network create my-scanner-net
docker run -d --name my-scanned-web --network my-scanner-net my-scanned-web:lab
# Select a reviewed ZAP image and make reports writable by its runtime user first.
docker run --rm --network my-scanner-net -v "$PWD/reports:/zap/wrk:rw"   ghcr.io/zaproxy/zaproxy:YOUR_REVIEWED_TAG   zap-baseline.py -t http://my-scanned-web:8080 -r combined-web.html
```

**Check before continuing:** Source, image and web reports are not treated as interchangeable evidence.

## Step 6 — Fix and verify one issue per layer

**Where:** Your source files and report notes.

Remove/rotate a genuine secret if one exists, correct an IaC setting, update a selected vulnerable package/image dependency and investigate a web finding. Rescan the same inputs, retaining the original results and explaining any unresolved risk.

**Check before continuing:** Your evidence records specific fixes and remaining findings rather than a blanket secure label.

## Step 7 — Add your own manual CI check

**Where:** Your own repository → .github/workflows.

Implement these commands as separate, version-pinned jobs using workflow_dispatch while building the lab. Give source scans read-only repository permissions, isolate web targets, retain only safe artifacts and keep deployment authority separate.

```bash
docker rm -f my-scanned-web
docker network rm my-scanner-net
```

**Check before continuing:** The pipeline can run against your own authored files without starting cloud services.

## Verification and your own screenshots

| Evidence | What to record | Your result |
| --- | --- | --- |
| New build | Your own files/resource settings and tool versions | Not yet recorded |
| Working path | The actual successful request, configuration or recovery result | Not yet recorded |
| Failure boundary | A meaningful denied, malformed, stale or failed case | Not yet recorded |
| Recovery / cleanup | What you restored or removed and what remains billed | Not yet recorded |

Capture your own architecture/configuration, one working result and one failure/recovery result. Keep tokens, credentials, personal records and private identifiers out of public screenshots. The architecture diagram explains the design; record your own results rather than treating it as execution evidence.

## Troubleshooting order

1. Confirm the named file, working directory and selected tool/interpreter.
2. Check the exact input and resource/account selected for the failing step.
3. Separate identity permission, network/DNS reachability and application validation.
4. Keep the actual error and reconcile an unknown write outcome before repeating it; do not widen access or repeat paid operations blindly.

The numbered steps describe a build procedure. Local syntax checks, an accepted API request, a completed hosted operation and a human verification are different evidence levels; fill in the verification table with what you actually observed.

## Official implementation references

- [trivy.dev — docs](https://trivy.dev/latest/docs/)
- [www.checkov.io — www.checkov.io](https://www.checkov.io/)
- [github.com — trufflehog](https://github.com/trufflesecurity/trufflehog)
- [www.zaproxy.org — baseline-scan](https://www.zaproxy.org/docs/docker/baseline-scan/)
- [docs.docker.com — #dockerignore-files](https://docs.docker.com/build/concepts/context/#dockerignore-files)

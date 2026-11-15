# Build your own from scratch: Checkov Azure Infrastructure Security

Your own Checkov scan of a Terraform file you create, followed by a documented fix and rescan.

Start with a new folder, your own files and your own accounts. The numbered steps below describe the build; no portfolio repository checkout is required. The existing implementation/evidence elsewhere in this repository is a separate reference, not a claim that your new build has already passed.

## Prerequisites

Your editor and Checkov prerequisites; a fresh lab folder. This source-only scan needs no Azure deployment or credentials; do not apply the deliberately weak fixture.

Use Bash on Linux/macOS/WSL for Bash blocks and PowerShell for PowerShell blocks. Select the tool versions supported by the official sources below, record the versions you actually install and retain generated dependency locks. Cloud resources, scanner downloads, logs and external AI calls can create costs; review the stated scope before enabling them.

## Create your project folder

Choose a new folder name. These first commands create a blank project; an optional `git init` gives it its own history. Create parent directories in your editor when a later step introduces a nested file.

```bash
mkdir my-checkov-azure-infrastructure-security
cd my-checkov-azure-infrastructure-security
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

## Step 1 — Choose the control and record the tool

**Where:** Your workstation.

Create a Python virtual environment, install Checkov in it and record the resolved package versions. Use the matching platform/interpreter and retain your dependency lock; do not install it globally over unrelated tools.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install checkov
.venv/bin/python -m pip freeze > requirements.lock.txt
.venv/bin/checkov --version
```

**Check before continuing:** The tool version is recorded and its prerequisite check succeeds.

## Step 2 — Create your test infrastructure file

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

## Step 3 — Run and retain the first scan

**Where:** Your project root.

Create a reports folder and run the command below. Retain the original output and exit status so a later successful scan does not erase what you found.

```bash
mkdir -p reports
.venv/bin/checkov --directory infra --framework terraform --download-external-modules false --output json > reports/checkov.json
```

**Check before continuing:** A parseable report exists; an empty or failed scan is not passed off as success.

## Step 4 — Read the finding in context

**Where:** The JSON report and infra/main.tf.

Inspect the failed TLS rule and resource, change TLS1_0 to TLS1_2, then rerun the same scan. Checkov findings normally produce a nonzero exit; distinguish policy findings from parsing or tool-execution errors.

**Check before continuing:** Your before/after record identifies the exact setting you corrected.

## Step 5 — Prove the changed result

**Where:** Your terminal.

Save a second report under a different filename and compare rule/resource outcomes with the first. Record unresolved findings with an owner and next action rather than deleting scanner rules or claiming scan success means the design is secure.

**Check before continuing:** The TLS correction is observable, and other risks remain visible.

## Step 6 — Add your own repeatable check

**Where:** Your own GitHub repository, optionally.

Create a manual workflow that installs your reviewed tool version, scans this file and retains safe reports. Keep credentials/private reports out of artifacts and use no Azure deployment permission for a source-only scan.

**Check before continuing:** A reader can reproduce the same input, tool version, finding and fix without your portfolio repository.

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

- [www.checkov.io — www.checkov.io](https://www.checkov.io/)

The walkthrough layout follows the prerequisites → creation/configuration → test → verification → troubleshooting → cleanup pattern of the [Splunk project reference](https://github.com/davidharris6/splunk-siem-log-analysis). Its Splunk-specific settings are not copied into unrelated projects.

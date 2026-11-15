# Build your own from scratch: Trufflehog Secret Detection

A secret-history exercise in a Git repository you create, using an unused local test key and no online credential verification.

Start with a new folder, your own files and your own accounts. The numbered steps below describe the build; no portfolio repository checkout is required. The existing implementation/evidence elsewhere in this repository is a separate reference, not a claim that your new build has already passed.

## Prerequisites

Git, OpenSSL and a reviewed TruffleHog installation. Use a disposable repository only; never add an actual cloud credential or private employee data.

Use Bash on Linux/macOS/WSL for Bash blocks and PowerShell for PowerShell blocks. Select the tool versions supported by the official sources below, record the versions you actually install and retain generated dependency locks. Cloud resources, scanner downloads, logs and external AI calls can create costs; review the stated scope before enabling them.

## Create your project folder

Choose a new folder name. These first commands create a blank project; an optional `git init` gives it its own history. Create parent directories in your editor when a later step introduces a nested file.

```bash
mkdir my-trufflehog-secret-detection
cd my-trufflehog-secret-detection
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

## Step 1 — Initialize your own repository

**Where:** Your empty lab folder.

Initialize Git and set your own commit author if needed. Record the TruffleHog version and create no connection to a real provider account.

```bash
git init
trufflehog --version
```

**Check before continuing:** Your repository has no inherited portfolio history.

## Step 2 — Create an unused test-only key

**Where:** The disposable folder.

Generate a key solely for this exercise, never register its public key with any service, and commit it once. This deliberately creates a history finding without exposing a working cloud credential.

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out UNUSED_LAB_KEY.pem
git add UNUSED_LAB_KEY.pem
git commit -m "Add unused key for detection exercise"
```

**Check before continuing:** One disposable commit contains the test key.

## Step 3 — Delete the current file and inspect history

**Where:** The same repository.

Delete the unused key from the current tree and commit that deletion. Notice that Git can still read it from the earlier commit; deleting a working file is not history cleanup or credential revocation.

```bash
git rm UNUSED_LAB_KEY.pem
git commit -m "Remove unused key from current tree"
git log --oneline
```

**Check before continuing:** Your latest tree has no key file, while history still contains the test commit.

## Step 4 — Run the history scan

**Where:** Your terminal.

Run TruffleHog with online verification disabled and retain its output privately. Some output can contain the detected value, so do not upload a raw report to your public project.

```bash
trufflehog git "file://$PWD" --no-verification --json > ../private-secret-findings.json
```

**Check before continuing:** The scan examines your Git history; record the detected key candidate and tool outcome without publishing its bytes.

## Step 5 — Explain the remediation decision

**Where:** Your report notes.

For this unused key, record that no provider-side credential was ever active. For a genuine finding, revoke/rotate at the provider first, investigate use and then handle Git history and copies under the owning team process.

**Check before continuing:** You distinguish detection, revocation, investigation and history cleanup.

## Step 6 — Retire the disposable material

**Where:** Your lab folder.

Remove the entire disposable repository and private report only after saving a value-free finding summary. Do not rewrite a shared repository as an automatic cleanup step.

**Check before continuing:** No unused private key or raw secret-bearing report remains in your public evidence.

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

- [github.com — trufflehog](https://github.com/trufflesecurity/trufflehog)

The walkthrough layout follows the prerequisites → creation/configuration → test → verification → troubleshooting → cleanup pattern of the [Splunk project reference](https://github.com/davidharris6/splunk-siem-log-analysis). Its Splunk-specific settings are not copied into unrelated projects.

# Build your own: Layered Security Testing for an Azure Platform

This is a step-by-step build guide for an independent learning copy. Follow the numbered steps in order and record your own results. The included local implementation is not a complete deployment of the private business platform; cloud extensions are separate and must use your own authorized resources.

## What you will create

The four local tool models and triage evidence; actual scanner runs remain a separate stage.

## Prerequisites and working locations

| Location | What you need |
| --- | --- |
| Your workstation | Git and the runtime versions documented in [the command guide](../README.md#run-the-examples); use its package/lockfile instructions. |
| Bash, Linux or WSL terminal | The commands below use Bash syntax. Prepare Python 3.12; use the project's pinned dependency files. |
| PowerShell alternative | Use the PowerShell forms in the command guide, or run this Bash recipe in WSL; do not paste Bash loops into PowerShell. |
| Azure or external service | Not needed for default local tests. Any cloud extension requires your own account, target, permissions, budget and acceptance plan. |

Read [the existing validation scope](VALIDATION.md) before running anything. A recorded historical test result is not evidence that your new copy has passed.

## Step 1: Create your own workspace

**Where:** your workstation, in a new project folder.

1. Clone the public source below into a new directory; keep the source attribution and included license terms. This creates your local learning copy, not cloud resources.
2. Record the selected commit and tool versions before editing. If you later publish a fork, review any origin, hash or target bindings rather than disabling guards to make the fork pass.

```bash
git clone https://github.com/truthofsource/azure-devsecops-security-scanning.git
cd azure-devsecops-security-scanning
git rev-parse HEAD
git rev-parse --show-toplevel
git status --short
```

**Expected result:** the project files are present and you can identify the starting source. Continue from this repository root unless a command explicitly changes directory.

## Step 2: Prepare dependencies and build the local baseline

**Where:** the same workstation terminal.

1. Follow the runtime instructions and install only the dependencies selected by this project's files. Terraform provider downloads, optional browser downloads and scanner databases are separate prerequisites where the detailed guide identifies them.
2. Run these source-derived baseline commands one at a time and stop on an unexpected failure. Read any skipped integration cases; a skip is not a successful live check.

```bash
for tool in trufflehog checkov trivy zap; do
  (cd "tools/$tool" && python3 -B -m unittest discover -s scripts -p 'test_*.py' -v && python3 -B scripts/demo.py) || exit 1
done
```

**Expected result:** the selected tests finish without unexpected failures, and a demonstration command, where provided, produces fictional local decisions. These commands reproduce the included lab scope; they do not commission the live platform.

## Step 3: Make one project-specific change

**Where:** your editor, in your own local copy.

1. Start with [`tools/trivy/scripts/test_security_scanning.py`](../tools/trivy/scripts/test_security_scanning.py) in your own copy. Add a synthetic report inside a new Trivy test and explain which finding blocks the gate; then rerun all four local tool suites. Keep saved scanner reports, real secrets and live web targets out of this exercise.
2. Save your new case separately from the original acceptance records, then rerun the affected tests and the baseline. Do not edit recorded scanner results, screenshots or validation counts to manufacture a successful outcome.

**Expected result:** you can explain what you changed, why the result changed and which negative case still fails safely. An unexpected failure means investigate the implementation or setup, not remove the failing check.

## Step 4: Verify behavior and capture your own evidence

**Where:** the test output, local viewer where supplied, and your private evidence folder.

1. If the project supplies a viewer, use its startup command in [the command guide](../README.md#run-the-examples); keep long-running preview servers in a separate terminal. Follow its exact loopback address and stop it with Ctrl+C when finished; for a command-line-only example, inspect its terminal output and generated files instead.
2. Compare your own output with [the proof and limits](../README.md#proof-it-works), then record source version, command, expected result, observed result and unresolved work. Capture screenshots of your own fictional output rather than presenting the existing screenshots as your execution.

**Expected result:** The four local tool models and triage evidence; actual scanner runs remain a separate stage. Your evidence must say whether it covers local logic, a real tool run, a hosted service or a human observation.

### Start the local preview

Open a second terminal in the same repository root printed by `git rev-parse --show-toplevel`. Run the command below from that root, after the baseline has passed; it stays running while you use the preview.

```bash
(cd tools/trivy && python3 -B scripts/preview.py --port 8138)
```

Open [http://127.0.0.1:8138](http://127.0.0.1:8138). This is the Trivy component viewer, not a combined scanner dashboard; the other components have their own command guides. The subshell keeps your main working directory unchanged.

The command uses the same Python environment as the baseline where Python is required. This guide uses an explicit virtual-environment executable rather than activating it; when following other project examples that say `python`, use that same executable if the project has a `.venv`. In WSL, keep the clone and its virtual environment in the same Linux environment; do not reuse a Windows `.venv`.

Keep one preview per listening port. Stop your own earlier preview with Ctrl+C before starting another one on that port, or use only a port override documented by the project. If you stop the preview, rerun only its startup command; you do not need to rebuild or redeploy cloud services.

## Step 5: Plan an independent cloud extension, if needed

**Where:** your own architecture/configuration files first; a separately authorized lab subscription only later.

1. Read the implementation and infrastructure references linked below. Substitute your own names, identities, address ranges and service settings in an isolated environment; a public reference may contain only selected components and is not authority to apply someone else's production state.
2. List the missing integrations and acceptance checks before deployment: runtime hosting, permissions, network/DNS paths, secrets, source data, notification or provider access as applicable. Keep disabled examples disabled until their specific dependencies, costs and cleanup are understood.

**Expected result:** a scoped extension plan with owners and explicit acceptance criteria, not a claim that the full service is deployed. No cloud `apply`, scanner targeting, paid operation or provider sign-in is implied by the local recipe.

- [Validation](VALIDATION.md)
- [Lessons Learned](LESSONS-LEARNED.md)

## Step 6: Troubleshoot, close out and explain what you built

**Where:** your project folder and the operating guide for any environment you actually created.

1. Check the failing stage in order: working directory and runtime, dependencies, test input, configuration, then any separately enabled service. Preserve the error and consult the existing troubleshooting lessons before widening permissions or changing the target.
2. Stop only the viewers/containers you started, retain your useful evidence and remove only resources belonging to your own reviewed lab. A local-only run needs no cloud deletion; if you created cloud resources, verify residual storage/address/monitoring charges rather than assuming compute stop removes all cost.

**Finish checklist:** explain the business problem, show your own change and verification, describe one failure/recovery case, identify limitations and name the next owner action. Keep credentials and business records out of public commits and screenshots.

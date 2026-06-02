# GCloud Sandbox Scripts

These scripts create and use a disposable Google Cloud VM for `unsus` dynamic sandbox testing when local Docker is unavailable.

No host secrets are copied. No real malware is used in fixture or benign remote npm validation flows. Real malicious package testing is available only through the explicit manifest-driven readiness workflow.

## Files

- `create-sandbox-vm.sh`: creates or prepares one VM with Docker, Node/npm, git, rsync, tar, and unzip.
- `sync-repo-to-vm.sh`: copies this repo to the VM using a tar archive with credential exclusions, then runs `npm install --ignore-scripts`, `npm run typecheck`, and `npm test`.
- `run-fixture-on-vm.sh`: runs only harmless local fixture dynamic scans and copies output logs to `artifacts/gcloud-sandbox/`.
- `run-remote-npm-on-vm.sh`: opt-in remote npm dynamic scan. Fetches on the VM only and is still for benign package checks, not real malware.
- `check-malware-readiness.sh`: verifies the configured disposable VM before real malicious payload testing.
- `run-malicious-samples-on-vm.sh`: explicit, manifest-driven real malicious sample runner for reviewed npm package specs.
- `status-sandbox-vm.sh`: describes only the configured VM.
- `destroy-sandbox-vm.sh`: deletes only the configured VM after confirmation.

## Required Environment

```bash
export UNSUS_GCLOUD_PROJECT="my-project"
export UNSUS_GCLOUD_ZONE="asia-south1-a"
export UNSUS_GCLOUD_VM_NAME="unsus-sandbox-dev"
```

Optional:

```bash
export UNSUS_GCLOUD_MACHINE_TYPE="e2-small"
export UNSUS_GCLOUD_DISK_SIZE="20GB"
export UNSUS_GCLOUD_IMAGE_FAMILY="debian-12"
export UNSUS_GCLOUD_IMAGE_PROJECT="debian-cloud"
```

## Flow

```bash
./scripts/gcloud/create-sandbox-vm.sh
./scripts/gcloud/sync-repo-to-vm.sh
./scripts/gcloud/run-fixture-on-vm.sh
./scripts/gcloud/destroy-sandbox-vm.sh
```

The VM can cost money while it exists. Delete it when done.

## Benign Remote Npm Dry Run

Only after the fixture flow passes, you can run a benign remote npm scan:

```bash
export UNSUS_REMOTE_NPM_PACKAGE="is-number@7.0.0"
export UNSUS_ALLOW_REMOTE_NPM_DYNAMIC=1
./scripts/gcloud/run-remote-npm-on-vm.sh
```

Do not use real malware in the benign remote npm workflow. Real malicious payload testing requires:

```bash
export UNSUS_MALWARE_SAMPLE_MANIFEST="artifacts/malware-lab/samples.json"
export UNSUS_REAL_MALWARE_TESTING=I_ACCEPT_REAL_MALWARE_RISK
./scripts/gcloud/check-malware-readiness.sh
./scripts/gcloud/run-malicious-samples-on-vm.sh
./scripts/gcloud/destroy-sandbox-vm.sh
```

See `docs/malicious-payload-testing.md`. No host secrets are copied, and payload lifecycle code must not run on the host.

## DataDog Candidate Flow

The DataDog dataset helper runs locally but reads metadata only:

```bash
npm run samples:datadog-npm -- \
  --output artifacts/malware-lab/datadog/npm-candidates.json \
  --limit 200

npm run samples:check-npm -- \
  --input artifacts/malware-lab/datadog/npm-candidates.json \
  --output artifacts/malware-lab/datadog/npm-available.json \
  --json
```

Use the generated availability manifest with `run-malicious-samples-on-vm.sh` only after reviewing the package specs.

# GCloud Sandbox Scripts

These scripts create and use a disposable Google Cloud VM for `unsus` dynamic sandbox testing when local Docker is unavailable.

No host secrets are copied. No real malware should be used. Remote npm dynamic analysis is intentionally not enabled yet.

## Files

- `create-sandbox-vm.sh`: creates or prepares one VM with Docker, Node/npm, git, rsync, tar, and unzip.
- `sync-repo-to-vm.sh`: copies this repo to the VM using a tar archive with credential exclusions, then runs `npm install --ignore-scripts`, `npm run typecheck`, and `npm test`.
- `run-fixture-on-vm.sh`: runs only harmless local fixture dynamic scans and copies output logs to `artifacts/gcloud-sandbox/`.
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

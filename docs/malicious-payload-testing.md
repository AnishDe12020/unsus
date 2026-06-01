# Real Malicious Payload Testing

Unsus is not ready to casually sample real malware on a developer laptop. The only supported path for real malicious npm payload testing is a disposable GCloud VM that has already passed the readiness check.

Real payload lifecycle code must not run on the host.

## Readiness Gate

Before testing real malicious packages:

1. Create a disposable VM with `scripts/gcloud/create-sandbox-vm.sh`.
2. Sync the repo with `scripts/gcloud/sync-repo-to-vm.sh`.
3. Run harmless fixture scans with `scripts/gcloud/run-fixture-on-vm.sh`.
4. Run a benign remote npm scan with `scripts/gcloud/run-remote-npm-on-vm.sh`.
5. Run `scripts/gcloud/check-malware-readiness.sh`.
6. Prepare a reviewed sample manifest.
7. Destroy the VM after the run with `scripts/gcloud/destroy-sandbox-vm.sh`.

The readiness check verifies that the VM is running, has no attached service account, carries the Unsus sandbox labels, has Docker/Node/npm available, and has a synced built CLI.

## Sample Manifest

Do not commit real malicious package names to the repo by default. Keep local manifests under `artifacts/` or another intentionally ignored location.

Example shape:

```json
{
  "kind": "unsus-malicious-npm-sample-manifest",
  "samples": [
    {
      "id": "reviewed-sample-001",
      "package": "package-name@1.2.3",
      "source": "advisory or research note",
      "notes": "Why this sample is approved for disposable VM testing"
    }
  ]
}
```

Package specs are fetched on the VM, not on the host.

For building these manifests from advisory candidate lists, use the metadata-only workflow in `docs/real-world-sample-sourcing.md`.

## Running The Lab

```bash
export UNSUS_GCLOUD_PROJECT="my-project"
export UNSUS_GCLOUD_ZONE="asia-south1-a"
export UNSUS_GCLOUD_VM_NAME="unsus-sandbox-dev"
export UNSUS_MALWARE_SAMPLE_MANIFEST="artifacts/malware-lab/samples.json"
export UNSUS_MALWARE_ARTIFACT_LABEL="first-reviewed-run"
export UNSUS_REAL_MALWARE_TESTING=I_ACCEPT_REAL_MALWARE_RISK

./scripts/gcloud/check-malware-readiness.sh
./scripts/gcloud/run-malicious-samples-on-vm.sh
./scripts/gcloud/destroy-sandbox-vm.sh
```

The exact `UNSUS_REAL_MALWARE_TESTING=I_ACCEPT_REAL_MALWARE_RISK` opt-in is required so this cannot happen by accident.

## What Is Copied Back

Only scanner reports, stderr summaries, and per-sample metadata are copied to `artifacts/gcloud-malware-lab/<label>/logs.tar.gz`.

The workflow must not copy:

- host secrets
- host home directory contents
- `.npmrc`
- `.env`
- `.ssh`
- `.aws`
- `.config/gcloud`
- VM temp package workspaces
- Docker workspaces

## Current Limitations

- Docker lifecycle execution uses `--network=none`, but Unsus does not yet trace attempted network syscalls.
- Remote npm package tarballs are fetched and extracted on the VM host before lifecycle scripts are run inside Docker.
- This is package behavior testing, not full malware reverse engineering.
- Native sandbox escape research is out of scope.
- Do not use this workflow for samples that require live command-and-control infrastructure or networked detonation.

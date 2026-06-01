# GCloud Disposable Sandbox

Use this workflow when local Docker or OrbStack is unavailable and you need to run harmless `unsus` fixture dynamic scans in an isolated cloud VM.

## Why A Disposable VM

Dynamic package behavior should not execute on the developer host. The VM is disposable, can be deleted after a test run, and keeps host files away from Docker lifecycle execution.

This is still not a malware lab. No real malware should be used in this workflow.

## What Gets Copied

`sync-repo-to-vm.sh` copies a tar archive of this repository to the VM, normally under `/tmp/unsus`.

It excludes:

- `.git`
- `node_modules`
- `dist`
- `.env` and `.env.*`
- `.npmrc`
- `.ssh`
- `.aws`
- `.config`
- credential-looking key/token/secret files

No host secrets, home directory, SSH keys, npm tokens, GitHub tokens, cloud credentials, `.config/gcloud`, `.env`, `.npmrc`, `.ssh`, or `.aws` directories should be copied.

## What Runs On The VM

The sync script runs:

```bash
npm install --ignore-scripts
npm run typecheck
npm test
```

The fixture runner then runs only local fixture scans:

```bash
node packages/cli/dist/index.js scan fixtures/suspicious/postinstall-env-network --dynamic
node packages/cli/dist/index.js scan fixtures/benign/install-script-build-package --dynamic
```

Package lifecycle execution still happens inside Docker on the VM. The Docker container uses no network, dropped capabilities, resource limits, a PID limit, tmpfs, and sanitized fake environment variables.

Remote npm dynamic analysis is not enabled yet. Do not use this flow for real suspicious packages or real malware.

## Example Flow

```bash
export UNSUS_GCLOUD_PROJECT="my-project"
export UNSUS_GCLOUD_ZONE="asia-south1-a"
export UNSUS_GCLOUD_VM_NAME="unsus-sandbox-dev"

./scripts/gcloud/create-sandbox-vm.sh
./scripts/gcloud/sync-repo-to-vm.sh
./scripts/gcloud/run-fixture-on-vm.sh
./scripts/gcloud/destroy-sandbox-vm.sh
```

## Cost Warning

The VM, boot disk, and any network/storage usage may cost money while the VM exists. The scripts print what they are about to create or delete. Delete the VM when done:

```bash
./scripts/gcloud/destroy-sandbox-vm.sh
```

## Service Account Safety

`create-sandbox-vm.sh` uses `--no-service-account`, which was verified locally via:

```bash
gcloud compute instances create --help
```

Do not run `gcloud auth login` inside the VM. Do not copy local `~/.config/gcloud` into the VM.

## Later Remote Npm Dynamic Analysis

A later phase can add an explicit opt-in remote npm dynamic workflow. That should fetch packages inside the VM, avoid host secrets, keep Docker no-network lifecycle execution, and require an explicit review before enabling real package samples.

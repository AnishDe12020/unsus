#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${script_dir}/lib.sh"

project="$(unsus_gcloud_project)"
zone="$(unsus_gcloud_zone)"
vm_name="${UNSUS_GCLOUD_VM_NAME:-unsus-sandbox-dev}"
machine_type="${UNSUS_GCLOUD_MACHINE_TYPE:-e2-small}"
disk_size="${UNSUS_GCLOUD_DISK_SIZE:-20GB}"
image_family="${UNSUS_GCLOUD_IMAGE_FAMILY:-debian-12}"
image_project="${UNSUS_GCLOUD_IMAGE_PROJECT:-debian-cloud}"

cat <<INFO
UNSUS GCLOUD SANDBOX VM CREATE PLAN

Cost warning: this command may create billable Google Cloud resources.

Project:      ${project}
Zone:         ${zone}
VM name:      ${vm_name}
Machine type: ${machine_type}
Boot disk:    ${disk_size}
Image:        ${image_project}/${image_family}
Labels:       app=unsus,purpose=sandbox,ttl=manual-delete

Safety:
- The VM is created with --no-service-account. Verified locally with:
  gcloud compute instances create --help
- No repository files are copied by this script.
- No host env vars, home directory, .env, .npmrc, .ssh, .aws, or gcloud config are copied.
- Docker lifecycle execution still happens inside no-network containers on the VM.
INFO

unsus_require_command gcloud

echo
echo "Active local gcloud account:"
gcloud auth list --filter=status:ACTIVE --format='table(account,status)'

if [[ -z "${UNSUS_GCLOUD_YES:-}" ]]; then
  echo
  read -r -p "Create or prepare this disposable VM? Type 'create ${vm_name}' to continue: " confirmation
  if [[ "${confirmation}" != "create ${vm_name}" ]]; then
    echo "Aborted."
    exit 1
  fi
fi

if gcloud compute instances describe "${vm_name}" \
  --project="${project}" \
  --zone="${zone}" \
  --format='value(name)' >/dev/null 2>&1; then
  echo "VM ${vm_name} already exists in ${project}/${zone}. Skipping create."
else
  gcloud compute instances create "${vm_name}" \
    --project="${project}" \
    --zone="${zone}" \
    --machine-type="${machine_type}" \
    --boot-disk-size="${disk_size}" \
    --image-family="${image_family}" \
    --image-project="${image_project}" \
    --labels=app=unsus,purpose=sandbox,ttl=manual-delete \
    --no-service-account \
    --no-scopes \
    --metadata=startup-script='#!/usr/bin/env bash
set -euxo pipefail
while fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock >/dev/null 2>&1; do sleep 5; done
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl git rsync tar unzip docker.io nodejs npm
systemctl enable --now docker
usermod -aG docker "$(logname 2>/dev/null || echo "${SUDO_USER:-}")" || true
'
fi

echo
echo "Waiting for SSH and ensuring sandbox dependencies are installed..."
prepare_command='set -euxo pipefail
unsus_wait_for_apt() {
  waited_seconds=0
  while sudo fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock >/dev/null 2>&1; do
    if [ "$waited_seconds" -ge 300 ]; then
      echo "Timed out waiting for apt/dpkg locks." >&2
      exit 1
    fi
    echo "Waiting for apt/dpkg lock..."
    sleep 5
    waited_seconds=$((waited_seconds + 5))
  done
}
unsus_wait_for_apt
sudo apt-get update
unsus_wait_for_apt
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl git rsync tar unzip docker.io nodejs npm
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER" || true
docker --version
node --version
npm --version
'

ssh_attempt=1
until gcloud compute ssh "${vm_name}" \
  --project="${project}" \
  --zone="${zone}" \
  --command="${prepare_command}" \
  --quiet; do
  if (( ssh_attempt >= 30 )); then
    echo "Timed out waiting for SSH to become ready." >&2
    exit 1
  fi
  echo "SSH not ready yet; retrying in 10s (${ssh_attempt}/30)..."
  ssh_attempt=$((ssh_attempt + 1))
  sleep 10
done

cat <<NEXT

VM is ready or preparation completed.

Next:
  ./scripts/gcloud/sync-repo-to-vm.sh
  ./scripts/gcloud/run-fixture-on-vm.sh
  ./scripts/gcloud/run-remote-npm-on-vm.sh

Destroy when done:
  ./scripts/gcloud/destroy-sandbox-vm.sh
NEXT

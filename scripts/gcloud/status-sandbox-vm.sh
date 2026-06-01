#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${script_dir}/lib.sh"

project="$(unsus_gcloud_project)"
zone="$(unsus_gcloud_zone)"
vm_name="${UNSUS_GCLOUD_VM_NAME:-unsus-sandbox-dev}"

echo "Inspecting configured unsus sandbox VM only."
echo "Project: ${project}"
echo "Zone: ${zone}"
echo "VM name: ${vm_name}"

gcloud compute instances describe "${vm_name}" \
  --project="${project}" \
  --zone="${zone}" \
  --format='table(name,zone.basename(),machineType.basename(),status,networkInterfaces[0].accessConfigs[0].natIP,labels.app,labels.purpose,labels.ttl)'

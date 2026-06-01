#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${script_dir}/lib.sh"

project="$(unsus_gcloud_project)"
zone="$(unsus_gcloud_zone)"
vm_name="${UNSUS_GCLOUD_VM_NAME:-unsus-sandbox-dev}"

cat <<INFO
UNSUS GCLOUD SANDBOX VM DELETE PLAN

This deletes exactly one VM:
Project: ${project}
Zone:    ${zone}
VM name: ${vm_name}

No disks, networks, images, or broader resources are selected by pattern.
INFO

if [[ "${UNSUS_GCLOUD_YES:-}" != "1" ]]; then
  echo
  read -r -p "Type 'delete ${vm_name}' to delete this VM: " confirmation
  if [[ "${confirmation}" != "delete ${vm_name}" ]]; then
    echo "Aborted."
    exit 1
  fi
fi

gcloud compute instances delete "${vm_name}" \
  --project="${project}" \
  --zone="${zone}" \
  --quiet

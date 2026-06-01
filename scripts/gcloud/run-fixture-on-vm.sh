#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
# shellcheck source=/dev/null
source "${script_dir}/lib.sh"

project="$(unsus_gcloud_project)"
zone="$(unsus_gcloud_zone)"
vm_name="${UNSUS_GCLOUD_VM_NAME:-unsus-sandbox-dev}"
remote_dir="${UNSUS_GCLOUD_REMOTE_DIR:-/tmp/unsus}"
artifact_dir="${repo_root}/artifacts/gcloud-sandbox"
remote_log_dir="/tmp/unsus-gcloud-sandbox-logs"

mkdir -p "${artifact_dir}"

echo "Running harmless local fixture dynamic scans on ${vm_name}."
echo "No remote npm package dynamic scans are run by this script."

gcloud compute ssh "${vm_name}" \
  --project="${project}" \
  --zone="${zone}" \
  --command="set -u
rm -rf '${remote_log_dir}'
mkdir -p '${remote_log_dir}'
cd '${remote_dir}'
docker pull node:22-bookworm-slim

set +e
node packages/cli/dist/index.js scan fixtures/suspicious/postinstall-env-network --dynamic > '${remote_log_dir}/suspicious-postinstall-env-network.txt' 2>&1
suspicious_exit=\$?
node packages/cli/dist/index.js scan fixtures/benign/install-script-build-package --dynamic > '${remote_log_dir}/benign-install-script-build-package.txt' 2>&1
benign_exit=\$?
set -e

printf 'suspicious_exit=%s\n' \"\$suspicious_exit\" | tee '${remote_log_dir}/exit-codes.txt'
printf 'benign_exit=%s\n' \"\$benign_exit\" | tee -a '${remote_log_dir}/exit-codes.txt'
tar -czf /tmp/unsus-gcloud-sandbox-logs.tar.gz -C '${remote_log_dir}' .
test \"\$suspicious_exit\" -eq 2
test \"\$benign_exit\" -eq 0
" \
  --quiet

gcloud compute scp "${vm_name}:/tmp/unsus-gcloud-sandbox-logs.tar.gz" "${artifact_dir}/logs.tar.gz" \
  --project="${project}" \
  --zone="${zone}" \
  --quiet

echo "Logs copied to ${artifact_dir}/logs.tar.gz"
echo "Only command output logs are copied; temp sandbox workspaces are not copied."

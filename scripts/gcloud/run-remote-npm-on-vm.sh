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
remote_log_dir="/tmp/unsus-gcloud-remote-npm-logs"
package_spec="${UNSUS_REMOTE_NPM_PACKAGE:-}"

if [[ -z "${package_spec}" ]]; then
  echo "Set UNSUS_REMOTE_NPM_PACKAGE to a benign package spec, for example is-number@7.0.0." >&2
  exit 2
fi

if [[ ! "${package_spec}" =~ ^(@[A-Za-z0-9._-]+/)?[A-Za-z0-9._-]+(@[A-Za-z0-9._~+^-]+)?$ ]]; then
  echo "UNSUS_REMOTE_NPM_PACKAGE contains unsupported characters: ${package_spec}" >&2
  exit 2
fi

if [[ "${UNSUS_ALLOW_REMOTE_NPM_DYNAMIC:-}" != "1" ]]; then
  cat >&2 <<WARN
Remote npm dynamic scanning is opt-in.

No real malware should be used here.
This script fetches the package from npm on the VM, not on the host.
Lifecycle execution, if present, happens inside Docker with --network=none.

Set UNSUS_ALLOW_REMOTE_NPM_DYNAMIC=1 after reviewing the package spec:
  ${package_spec}
WARN
  exit 2
fi

mkdir -p "${artifact_dir}"

cat <<INFO
UNSUS REMOTE NPM DYNAMIC SCAN

Package: ${package_spec}
Project: ${project}
Zone:    ${zone}
VM:      ${vm_name}

Safety:
- Package fetch happens on the VM, not on this host.
- No host env, home directory, npm token, GitHub token, or cloud credentials are copied.
- Docker lifecycle execution uses no network, sanitized env, dropped caps, and resource limits.
- No real malware should be used in this workflow yet.
INFO

gcloud compute ssh "${vm_name}" \
  --project="${project}" \
  --zone="${zone}" \
  --command="set -u
rm -rf '${remote_log_dir}'
mkdir -p '${remote_log_dir}'
cd '${remote_dir}'
docker pull node:22-bookworm-slim

set +e
node packages/cli/dist/index.js scan '${package_spec}' --dynamic --allow-remote-dynamic --json > '${remote_log_dir}/remote-npm-scan.json' 2> '${remote_log_dir}/remote-npm-scan.stderr'
scan_exit=\$?
set -e

printf 'package=%s\n' '${package_spec}' | tee '${remote_log_dir}/summary.txt'
printf 'scan_exit=%s\n' \"\$scan_exit\" | tee -a '${remote_log_dir}/summary.txt'
tar -czf /tmp/unsus-gcloud-remote-npm-logs.tar.gz -C '${remote_log_dir}' .
exit 0
" \
  --quiet

gcloud compute scp "${vm_name}:/tmp/unsus-gcloud-remote-npm-logs.tar.gz" "${artifact_dir}/remote-npm-logs.tar.gz" \
  --project="${project}" \
  --zone="${zone}" \
  --quiet

scan_exit="$(tar -xOzf "${artifact_dir}/remote-npm-logs.tar.gz" ./summary.txt | awk -F= '/^scan_exit=/{print $2}')"
echo "Remote npm scan exit: ${scan_exit}"
echo "Logs copied to ${artifact_dir}/remote-npm-logs.tar.gz"
exit "${scan_exit}"

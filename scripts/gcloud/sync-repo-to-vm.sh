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

echo "Syncing repo to ${vm_name}:${remote_dir}"
echo "Project: ${project}"
echo "Zone: ${zone}"
echo
echo "Safety: this sync excludes .git, node_modules, dist, .env, .npmrc, .ssh, .aws, .config, and credential-looking files."

tmp_tar="$(mktemp -t unsus-repo.XXXXXX.tar.gz)"
cleanup() {
  rm -f "${tmp_tar}"
}
trap cleanup EXIT

(
  cd "${repo_root}"
  export COPYFILE_DISABLE=1
  tar \
    --no-xattrs \
    --no-mac-metadata \
    --exclude='.git' \
    --exclude='node_modules' \
    --exclude='dist' \
    --exclude='*.tsbuildinfo' \
    --exclude='.env' \
    --exclude='.env.*' \
    --exclude='.npmrc' \
    --exclude='.ssh' \
    --exclude='.aws' \
    --exclude='.config' \
    --exclude='**/.env' \
    --exclude='**/.env.*' \
    --exclude='**/.npmrc' \
    --exclude='**/.ssh' \
    --exclude='**/.aws' \
    --exclude='**/.config' \
    --exclude='*token*' \
    --exclude='*secret*' \
    --exclude='*credential*' \
    --exclude='*.pem' \
    --exclude='*.key' \
    -czf "${tmp_tar}" .
)

gcloud compute ssh "${vm_name}" \
  --project="${project}" \
  --zone="${zone}" \
  --command="rm -rf '${remote_dir}' && mkdir -p '${remote_dir}'" \
  --quiet

gcloud compute scp "${tmp_tar}" "${vm_name}:/tmp/unsus-repo.tar.gz" \
  --project="${project}" \
  --zone="${zone}" \
  --quiet

gcloud compute ssh "${vm_name}" \
  --project="${project}" \
  --zone="${zone}" \
  --command="set -euxo pipefail
tar -xzf /tmp/unsus-repo.tar.gz -C '${remote_dir}'
rm -f /tmp/unsus-repo.tar.gz
cd '${remote_dir}'
npm install --ignore-scripts
npm run typecheck
npm test
" \
  --quiet

echo "Repo synced and verified on VM."

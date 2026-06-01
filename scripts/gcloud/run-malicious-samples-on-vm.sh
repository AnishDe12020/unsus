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
manifest="${UNSUS_MALWARE_SAMPLE_MANIFEST:-}"
artifact_label="${UNSUS_MALWARE_ARTIFACT_LABEL:-manual-real-payload-run}"
artifact_dir="${repo_root}/artifacts/gcloud-malware-lab/${artifact_label}"
remote_manifest="/tmp/unsus-malware-samples.json"
remote_log_dir="/tmp/unsus-gcloud-malware-lab-logs"

if [[ "${UNSUS_REAL_MALWARE_TESTING:-}" != "I_ACCEPT_REAL_MALWARE_RISK" ]]; then
  cat >&2 <<WARN
Real malicious payload testing is disabled by default.

This workflow fetches real npm package samples on a disposable VM and may analyze
known hostile package contents. Lifecycle execution must still happen only inside
Docker with --network=none.

To continue, set exactly:
  export UNSUS_REAL_MALWARE_TESTING=I_ACCEPT_REAL_MALWARE_RISK
WARN
  exit 2
fi

if [[ -z "${manifest}" ]]; then
  echo "Set UNSUS_MALWARE_SAMPLE_MANIFEST to a JSON manifest of package specs." >&2
  exit 2
fi

if [[ ! -f "${manifest}" ]]; then
  echo "Sample manifest does not exist: ${manifest}" >&2
  exit 2
fi

if [[ ! "${artifact_label}" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "UNSUS_MALWARE_ARTIFACT_LABEL must contain only letters, numbers, dot, underscore, or dash." >&2
  exit 2
fi

node --input-type=module - "${manifest}" <<'NODE'
import { readFileSync } from "node:fs";

const manifestPath = process.argv[2];
const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
if (manifest.kind !== "unsus-malicious-npm-sample-manifest") {
  throw new Error("manifest.kind must be unsus-malicious-npm-sample-manifest");
}
if (!Array.isArray(manifest.samples) || manifest.samples.length === 0) {
  throw new Error("manifest.samples must be a non-empty array");
}
const packagePattern = /^(@[A-Za-z0-9._-]+\/)?[A-Za-z0-9._-]+(@[A-Za-z0-9._~+^-]+)?$/;
const idPattern = /^[A-Za-z0-9._-]+$/;
for (const sample of manifest.samples) {
  if (!idPattern.test(sample.id ?? "")) {
    throw new Error(`invalid sample id: ${sample.id}`);
  }
  if (!packagePattern.test(sample.package ?? "")) {
    throw new Error(`invalid package spec for ${sample.id}`);
  }
}
NODE

"${script_dir}/check-malware-readiness.sh"

mkdir -p "${artifact_dir}"

cat <<INFO
UNSUS REAL MALICIOUS PAYLOAD SCAN PLAN

Project:  ${project}
Zone:     ${zone}
VM:       ${vm_name}
Manifest: ${manifest}
Artifacts:${artifact_dir}

Safety:
- Package fetch happens on the VM, not on this host.
- Host env vars, home directory, npm tokens, GitHub tokens, and cloud credentials are not copied.
- Lifecycle scripts execute only through Unsus dynamic analysis inside Docker with --network=none.
- Copied artifacts are limited to scanner stdout/stderr summaries and per-sample metadata.
- Destroy the VM immediately after the run:
  ./scripts/gcloud/destroy-sandbox-vm.sh
INFO

if [[ -z "${UNSUS_GCLOUD_YES:-}" ]]; then
  read -r -p "Run real malicious sample scan on ${vm_name}? Type 'run real samples' to continue: " confirmation
  if [[ "${confirmation}" != "run real samples" ]]; then
    echo "Aborted."
    exit 1
  fi
fi

gcloud compute scp "${manifest}" "${vm_name}:${remote_manifest}" \
  --project="${project}" \
  --zone="${zone}" \
  --quiet

gcloud compute ssh "${vm_name}" \
  --project="${project}" \
  --zone="${zone}" \
  --command="set -u
rm -rf '${remote_log_dir}'
mkdir -p '${remote_log_dir}'
cd '${remote_dir}'
docker pull node:22-bookworm-slim

node --input-type=module - '${remote_manifest}' > '${remote_log_dir}/samples.tsv' <<'NODE'
import { readFileSync } from 'node:fs';
const manifest = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const packagePattern = /^(@[A-Za-z0-9._-]+\\/)?[A-Za-z0-9._-]+(@[A-Za-z0-9._~+^-]+)?$/;
const idPattern = /^[A-Za-z0-9._-]+$/;
for (const sample of manifest.samples) {
  if (!idPattern.test(sample.id ?? '') || !packagePattern.test(sample.package ?? '')) {
    throw new Error('Invalid sample manifest entry');
  }
  console.log(sample.id + '\\t' + sample.package);
}
NODE

overall_exit=0
while IFS=\$'\\t' read -r sample_id package_spec; do
  [ -n \"\$sample_id\" ] || continue
  echo \"sample=\$sample_id package=\$package_spec\" | tee \"${remote_log_dir}/\${sample_id}.summary.txt\"
  set +e
  node packages/cli/dist/index.js scan \"\$package_spec\" --dynamic --allow-remote-dynamic --json > \"${remote_log_dir}/\${sample_id}.scan.json\" 2> \"${remote_log_dir}/\${sample_id}.stderr.txt\"
  scan_exit=\$?
  set -e
  printf 'scan_exit=%s\\n' \"\$scan_exit\" | tee -a \"${remote_log_dir}/\${sample_id}.summary.txt\"
  if [ \"\$scan_exit\" -eq 3 ]; then
    overall_exit=3
  fi
done < '${remote_log_dir}/samples.tsv'

cat > '${remote_log_dir}/README.txt' <<'README'
These are scanner reports and stderr summaries only. Temp package workspaces,
Docker workspaces, host home directories, and credential locations are not copied.
README

tar -czf /tmp/unsus-gcloud-malware-lab-logs.tar.gz -C '${remote_log_dir}' .
exit \"\$overall_exit\"
" \
  --quiet

gcloud compute scp "${vm_name}:/tmp/unsus-gcloud-malware-lab-logs.tar.gz" "${artifact_dir}/logs.tar.gz" \
  --project="${project}" \
  --zone="${zone}" \
  --quiet

echo "Logs copied to ${artifact_dir}/logs.tar.gz"
echo "Destroy the VM now:"
echo "  ./scripts/gcloud/destroy-sandbox-vm.sh"

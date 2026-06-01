# Real-World Sample Sourcing

Live npm is a weak source for confirmed-malicious regression tests. Packages and versions are often removed from npm after disclosure, which is the right outcome for users but bad for repeatable benchmarking.

Unsus should treat real-world test sourcing as a pipeline, not a single registry lookup.

## Source Tiers

1. Advisory metadata.
   Use OSV, GitHub advisories, vendor writeups, and incident reports to collect package names, exact versions, dates, and behavior claims. This tier is metadata-only.

2. Live npm availability.
   Check whether exact package versions are still in the npm packument. This should not download tarballs locally.

3. Quarantine archive.
   If npm removed the package, only use artifacts from an intentionally managed quarantine store. Do not keep these in git. Do not sync them through normal repo sync. Do not inspect or unpack them on the host.

4. Registry snapshot or private mirror.
   For repeatable tests, use a disposable VM to pull from an approved registry snapshot or private malware-lab mirror. The mirror must be treated as hostile content storage.

5. Synthetic reproduction.
   If the real artifact is unavailable, preserve the behavior as a harmless synthetic fixture and link it back to the advisory.

## Metadata-Only Availability Check

Prepare a local ignored candidate list under `artifacts/`:

```json
{
  "kind": "unsus-real-world-npm-candidate-list",
  "candidates": [
    {
      "id": "reviewed-advisory-001",
      "package": "package-name@1.2.3",
      "source": "https://osv.dev/vulnerability/example",
      "notes": "Why this is relevant"
    }
  ]
}
```

Then run:

```bash
node scripts/research/check-npm-sample-availability.mjs \
  --input artifacts/malware-lab/candidates.json \
  --output artifacts/malware-lab/available-samples.json \
  --json
```

This check is metadata-only. It queries npm package metadata with `fetch`; it does not use `npm view`, does not download tarballs locally, and does not execute package code.

The generated `available-samples.json` can be used by the disposable VM runner:

```bash
export UNSUS_MALWARE_SAMPLE_MANIFEST="artifacts/malware-lab/available-samples.json"
export UNSUS_REAL_MALWARE_TESTING=I_ACCEPT_REAL_MALWARE_RISK
./scripts/gcloud/run-malicious-samples-on-vm.sh
```

## Handling Removed From Npm Cases

If a sample is removed from npm:

- keep the advisory metadata;
- mark the exact version as unavailable in the availability report;
- add a synthetic fixture for the claimed behavior if useful;
- only use real archived tarballs from a quarantine or registry snapshot inside a disposable VM workflow.

Do not download tarballs locally. Do not transfer archived malicious tarballs through normal repo sync. Do not commit package names that should remain private. Do not copy host secrets into a VM or mirror.

## Future Work

- Add a VM-only runner for quarantined tarballs.
- Add a VM-only runner for private registry snapshots.
- Add provenance comparison between source repository snapshots and registry tarballs.
- Add behavior labels from advisory text so reports can compare expected malicious behavior with detected findings.

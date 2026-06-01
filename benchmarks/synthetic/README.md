# Unsus Synthetic Benchmark Corpus

This corpus is local-only and intentionally harmless. It gives Unsus repeatable examples for scanner behavior without using real malware or running unknown package lifecycle scripts on the host.

The suspicious fixtures use fake names such as `FAKE_TEST_TOKEN` and inert domains such as `example.invalid`. They are meant to be scanned as source text. Do not execute them directly on the host.

Run the corpus with:

```bash
npm run benchmark:synthetic
```

The runner builds the repo and executes `unsus scan` / `unsus diff` against local fixture directories only.

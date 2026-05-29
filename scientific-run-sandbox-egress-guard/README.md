# Scientific Run Sandbox Egress Guard

Self-contained slice for issue #14, focused on the executable environment and compute trigger requirements for Scientific/Engineering Data & Code Hosting.

The module evaluates synthetic notebook/script/model run plans before they are allowed into a reproducible compute queue. It checks pinned runtime images, container privilege settings, host mounts, network egress, restricted dataset handling, resource ceilings, scheduled rerun determinism, and output manifest coverage. It does not call external services, use credentials, or inspect private data.

## Run

```bash
npm install
npm test
npm run demo
npm run demo:video
```

The demo writes reviewer artifacts under `reports/`:

- `demo-output.json`
- `demo-report.md`
- `decision-matrix.svg`
- `sandbox-egress-demo.webm`

## Issue #14 Mapping

- Scalable storage and metadata-aware hosting: validates that run outputs have typed manifests, checksums, access state, and storage paths before export or preview.
- Executable environments: blocks unpinned runtime images, privileged containers, unsafe capabilities, writable host mounts, and missing resource ceilings.
- Sandboxed execution: enforces deny-by-default or reviewed allowlist egress for restricted inputs, prevents public outputs from restricted data without redaction approval, and flags unsafe command/network mismatch.
- Compute triggers and scheduled reruns: requires dataset version pins and deterministic seeds before scheduled reruns proceed.
- FAIR/reproducibility evidence: produces deterministic audit hashes plus JSON, Markdown, SVG, and video artifacts from synthetic sample plans.

## Review Notes

This is intentionally a narrow governance guard, not another broad FAIR manifest or artifact hosting baseline. It complements earlier #14 slices by deciding whether a hosted research artifact is safe to execute in a sandboxed reproduce-run before reviewers, sponsors, or public users can trigger it.

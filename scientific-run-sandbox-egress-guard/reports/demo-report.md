# Sandbox Egress Guard Report

| Run | Decision | Score | Input risk | Findings | Audit hash |
| --- | --- | ---: | --- | ---: | --- |
| safe-notebook-deny-egress | ALLOW | 100 | restricted | 0 | `1d048c373074` |
| restricted-open-egress | BLOCK | 0 | restricted | 7 | `737ceeea8dcd` |
| scheduled-rerun-needs-seed | HOLD | 80 | public | 2 | `4fa03c313027` |
| restricted-allowlist-review | HOLD | 90 | restricted | 1 | `d942cbd10139` |

## Required Actions

### safe-notebook-deny-egress
- No action required.

### restricted-open-egress
- Pin the Docker image with an immutable sha256 digest.
- Run the workload without privileged mode or privilege escalation.
- Drop dangerous capabilities from the sandbox profile.
- Use content-addressed artifact mounts or read-only mounts only.
- Use deny egress or a reviewed allowlist for restricted data.
- Route oversized runs to manual compute review.
- Keep output private or attach data steward redaction approval.

### scheduled-rerun-needs-seed
- Pin every scheduled input to a dataset version.
- Record a deterministic seed or explain why the run is deterministic without one.

### restricted-allowlist-review
- Record reviewer approval for each allowed destination.

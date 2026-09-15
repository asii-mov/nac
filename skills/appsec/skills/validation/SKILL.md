# Adversarial source validation 1.0.0

Compatibility: nac-source-review-v1. Stage: validation. Requires evidence discipline.
Hypothesis: attempting to disprove candidate prerequisites exposes weak chains.
This bootstrap hypothesis is not a proven improvement.

Read the candidate's supplied evidence and pinned source. Independently check input
control, reachability, guards, deployment assumptions and impact. Search for concrete
counterevidence. Keep source-supported conclusions separate from runtime claims.

Submit a structured partial result identifying supported and unsupported links. If
proof needs execution, record an unsupported-experiment blocker. This source-only
profile cannot reproduce exploits, certify impact, modify code or declare remediation.
Evaluation cases: unreachable code, correct guard, wrong dependency version and
plausible source evidence that still needs a controlled runtime experiment.

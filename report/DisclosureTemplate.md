# Responsible Disclosure Report Template

## Summary
- Title:
- Date:
- Reporter Contact:
- Affected Systems:

## Impact
- User-facing impact (tick stalls, match resets, service degradation):
- Scope (regions, percent of matches):
- Severity (Low/Medium/High/Critical):

## Evidence Expectations
- Reproducible logs or metrics (no exploit steps).
- Timing and frequency data.
- Sanitized packet traces if applicable.

## Proposed Mitigations
- Address validation and anti-amplification enforcement.
- Bounded parsing and sandboxing.
- Multi-dimensional rate limiting and queue guard.
- Risk scoring and greylist controls.

## Rollout Plan
- Canary in a single region.
- Gradual expansion with success metrics.
- Rollback criteria.

## Validation Metrics
- Tick time p99.
- Drop ratio by reason.
- Safe mode activation rate.
- False-positive enforcement rate.

## Notes
- Defensive-only guidance. No offensive details included.

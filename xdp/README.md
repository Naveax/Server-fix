# XDP/eBPF Policy Skeleton (Defensive)

## Goals
- Early drop of obviously invalid traffic.
- Fast block/grey list maps.
- PPS/bytes caps by source prefix.
- Low-overhead sampling for observability.

## Suggested Rules
- Drop packets outside allowed ports.
- Drop packets below minimum or above maximum sizes.
- Apply coarse per-prefix PPS/byte caps.
- Enforce fast blocklist and greylist maps.
- Sample 1/N packets for metadata export.

## Notes
- Keep rules simple and O(1).
- Avoid deep parsing in XDP.
- Use a control plane to update maps.

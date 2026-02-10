# Parser Sandbox

## Purpose
- Run untrusted decode in a separate worker process.
- Contain crashes and enforce timeouts/backpressure.

## Protocol (Reference)
- Client sends: 2-byte big-endian length + payload bytes.
- Worker returns: 1 byte status (0 = OK, 1 = Invalid).

## Notes
- This is a reference skeleton. Production deployments should harden IPC and lifecycle management.

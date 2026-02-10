# Optional RLBot Notes

The default RocketLeagueServerFix build and docs target vendor-agnostic UDP edge mitigation.
RLBot-specific guard functionality is optional and isolated in the `nx_fbs_guard` crate.

## RLBot v5 Guard Wiring
1. RLBotServer default: `127.0.0.1:23234`
2. Start guard:
   `cargo run -p nx_fbs_guard -- --listen 127.0.0.1:23235 --upstream 127.0.0.1:23234`
3. Point bots to guard:
   - `RLBOT_SERVER_IP=127.0.0.1`
   - `RLBOT_SERVER_PORT=23235`

## Packet Format
RLBot v5 TCP framing used by `nx_fbs_guard`:
`u16` big-endian length prefix followed by FlatBuffers payload bytes.

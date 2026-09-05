# Phase 5 — Forward Secrecy

Extends the Phase 4 E2E session with automatic key rotation every 60 seconds, so a
compromised key only exposes a single 60-second window of chat instead of the whole
conversation.

## Files in This Phase

- `protocol.cpp` / `protocol.hpp` — message parsing (unchanged)
- `framing.cpp` / `framing.hpp` — length-prefixed framing (unchanged)
- `dh.cpp` / `dh.hpp` — Diffie–Hellman, now re-run every 60s per active E2E session
- `crypto.cpp` / `crypto.hpp` — SHA-256 + AES-GCM (unchanged from Phase 4)
- `server_auth.cpp` / `server_auth.hpp` — certificate validation (unchanged)
- `server.cpp` — unchanged routing logic
- `client.cpp` — adds the 60s rekey timer and initiator tie-breaking logic
- `compileServer` / `compileClient` — build scripts for this phase

## VM Topology

Same as Phase 4 — Server, C1, and C2 only.

| VM | Role | Host-only IP |
|---|---|---|
| Server VM | S | `192.168.56.102` |
| Client1 VM | C1 | `192.168.56.101` |
| Client2 VM | C2 | `192.168.56.103` |

## Dependencies

Same as Phase 4 — no new libraries.

```bash
sudo apt update
sudo apt install g++ make libssl-dev openssl
```

## Build

```bash
cd phase5/

chmod +x compileServer compileClient

./compileServer   # produces server.exe
./compileClient   # produces client.exe
```

## Run

Server VM:
```bash
./server.exe
```

Each Client VM:
```bash
./client.exe <SERVER_IP> 5000
```

Log in on both, then start an E2E session as in Phase 4:
```
> login Harshit          # on C1
> login Dhanush          # on C2
> /chat Dhanush          # on C1
> /e2e Dhanush           # on C1
```

Leave both clients running and chatting occasionally. Every 60 seconds the initiator
(the client whose username sorts first alphabetically) sends a rekey request; both
sides log the new key's fingerprint and a timestamp. Let it run past at least two
rotations to capture evidence for the report.


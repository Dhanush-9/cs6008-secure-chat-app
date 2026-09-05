# Phase 4 — End-to-End Encryption Between Clients

Adds a second, inner layer of encryption directly between C1 and C2, on top of the
Phase 3 client-server link. The server keeps routing by username but can no longer
read chat content.

## Files in This Phase

- `protocol.cpp` / `protocol.hpp` — message parsing
- `framing.cpp` / `framing.hpp` — length-prefixed framing 
- `dh.cpp` / `dh.hpp` — Diffie–Hellman, now also used for the peer-to-peer C1↔C2 exchange
- `crypto.cpp` / `crypto.hpp` — SHA-256 + AES-GCM, now also used for the inner E2E layer
- `server_auth.cpp` / `server_auth.hpp` — certificate validation (unchanged from Phase 3)
- `server.cpp` — unchanged routing logic; relays `__E2E_INIT__` / `__E2E_ACK__` / `__E2E_MSG__` as opaque payloads
- `client.cpp` — adds the `/e2e username` handshake and double-encryption of chat messages
- `compileServer` / `compileClient` — build scripts for this phase

## VM Topology

Only the Server, C1, and C2 VMs are needed for this phase (no attacker VM).

| VM | Role | Host-only IP |
|---|---|---|
| Server VM | S | `192.168.56.102` |
| Client1 VM | C1 | `192.168.56.101` |
| Client2 VM | C2 | `192.168.56.103` |

Reuse the same `ca.crt` on both client VMs from Phase 3.

## Dependencies

Same as Phase 3 — no new libraries.

```bash
sudo apt update
sudo apt install g++ make libssl-dev openssl
```

## Build

```bash
cd phase4/

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

Log in on both, then establish an E2E session:
```
> login Harshit          # on C1
> login Dhanush          # on C2
> /chat Dhanush          # on C1
> /e2e Dhanush           # on C1 — initiates the E2E handshake
```
Both sides print a fingerprint of the derived E2E key once the handshake completes —
these should match. Chat normally after that; messages typed in the active chat are
now wrapped in `__E2E_MSG__` and double-encrypted.

## Verifying Server-Blindness

Messages sent **before** `/e2e` should be readable in the log (matching Phase 2/3 behaviour). Messages sent **after** the E2E session is established should appear only as opaque hex under `__E2E_MSG__`, proving the server can route them but not read them.

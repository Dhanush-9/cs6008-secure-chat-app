# Phase 3 — Server Authentication via PKI

Adds an X.509 certificate handshake before the Phase 2 DH exchange: the server
presents a CA-signed certificate, the client validates it, then challenges the server
to prove it holds the matching private key. This is what finally stops the Phase 2
MITM attack.

## Files in This Phase

- `protocol.cpp` / `protocol.hpp` — message parsing, added additional formats CERT, CHALLENGE, CHALLENGE_RESP.
- `framing.cpp` / `framing.hpp` — length-prefixed framing
- `dh.cpp` / `dh.hpp` — Diffie–Hellman (unchanged from Phase 2)
- `crypto.cpp` / `crypto.hpp` — SHA-256 + AES-GCM (unchanged from Phase 2)
- `server_auth.cpp` / `server_auth.hpp` — certificate validation and challenge/response
- `server.cpp` — now sends its certificate and signs the client's challenge
- `client.cpp` — now validates the server's certificate before proceeding to DH
- `mitm.cpp` — updated attacker proxy for the re-attempt task
- `compileServer` / `compileClient` — build scripts for this phase

## VM Topology

Same four VMs as Phase 2 (Server, C1, C2, Mallory) on the same host-only network.

| VM | Role | Host-only IP |
|---|---|---|
| Server VM | S | `192.168.56.102` |
| Client1 VM | C1 | `192.168.56.101` |
| Client2 VM | C2 | `192.168.56.103` |
| Mallory VM | Attacker | `192.168.56.104` |

The CA is hosted on the Server VM. Both client VMs need a copy of `ca.crt` (the CA's
public certificate) to validate against — copy it over with `scp` before testing.
The certificate's Common Name (CN) must match the value the clients expect
(e.g. `<SERVER_IP>` or the server's hostname), since the client checks this during
validation.

## Dependencies

```bash
sudo apt update
sudo apt install g++ make libssl-dev openssl
```

## One-Time CA and Server Certificate Setup

Run these on the Server VM (see the report for the full command reference):

```bash
mkdir -p ca server

# CA key + self-signed root cert
openssl genrsa -out ca/ca.key 2048
openssl req -x509 -new -nodes -key ca/ca.key -sha256 -days 365 -out ca/ca.crt

# Server key + CSR
openssl genrsa -out server/server.key 2048
openssl req -new -key server/server.key -out server/server.csr
# When prompted for Common Name, enter <SERVER_IP> (or the server's hostname)

# CA signs the server's CSR
openssl x509 -req -in server/server.csr -CA ca/ca.crt -CAkey ca/ca.key \
  -CAcreateserial -out server/server.crt -days 365 -sha256
```

Copy `ca/ca.crt` to both client VMs.

## Build

Use the provided scripts:
```bash
cd phase3/

chmod +x compileServer compileClient

./compileServer   # produces server.exe
./compileClient   # produces client.exe
```

For the MITM proxy (not covered by the scripts above, links the same DH/crypto code):
```bash
chmod +x compileMitm

./compileMitm   #produces mitm.exe
```
## Run — Normal  Flow

Server VM:
```bash
./server.exe
```

Each Client VM (needs `ca.crt` in the same directory):
```bash
./client.exe <SERVER_IP> 5000
```
The client should print certificate validation and proof-of-possession success before
the DH handshake proceeds.

## Run — MITM Re-Attempt (should now fail)

**Case 1 — self-signed certificate:**
```bash
./mitm.exe <SERVER_IP> 5000        # Mallory VM, attack mode 1
./client.exe <MALLORY_IP> 5001     # Client VM
```
The client should reject the certificate and abort before any DH exchange.

**Case 2 — real certificate, no private key:**
```bash
./mitm.exe <SERVER_IP> 5000 2      # Mallory VM, attack mode 2
./client.exe <MALLORY_IP> 5001     # Client VM
```
Certificate validation succeeds, but the proof-of-possession challenge should fail and
the client should abort.

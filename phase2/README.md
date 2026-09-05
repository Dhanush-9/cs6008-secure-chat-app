# Phase 2 — Client-Server Confidentiality via Diffie–Hellman

Adds a Diffie–Hellman key exchange (RFC 3526 MODP Group 14) between each client and the server, an AES key derived by hashing the shared secret, and AES-GCM encryption of every message. Also includes a MITM proxy that breaks this phase, since DH alone doesn't authenticate anyone.

## Files in This Phase

- `protocol.cpp` / `protocol.hpp` — message parsing, added additional format DH_HELLO.
- `framing.cpp` / `framing.hpp` — length-prefixed framing (unchanged from Phase 1)
- `dh.cpp` / `dh.hpp` — Diffie–Hellman modular exponentiation, from scratch
- `crypto.cpp` / `crypto.hpp` — SHA-256 key derivation and AES-GCM encrypt/decrypt
- `server.cpp` — chat server, now performs DH per-connection
- `client.cpp` — chat client, now performs DH on connect
- `mitm.cpp` — attacker proxy for the MITM task
- `compileServer` / `compileClient` — build scripts for this phase

## VM Topology

Same Server/C1/C2 VMs as Phase 1, plus a fourth VM for the attack task:

| VM | Role | Host-only IP |
|---|---|---|
| Server VM | S | `192.168.56.102` |
| Client1 VM | C1 | `192.168.56.101` |
| Client2 VM | C2 | `192.168.56.103` |
| Mallory VM | Attacker | `192.168.56.104` |


All four VMs sit on the same host-only network. Confirm connectivity with `ping`
between every pair before testing.

## Dependencies

Needs OpenSSL's crypto primitives (BIGNUM for modexp, EVP for AES-GCM/SHA-256) **not** OpenSSL's DH or SSL/TLS API, per the assignment rules.

```bash
sudo apt update
sudo apt install g++ make libssl-dev
```

## Build

Use the provided scripts:
```bash
cd phase2/

chmod +x compileServer compileClient

./compileServer   # produces server.exe
./compileClient   # produces client.exe
```

For the MITM proxy (not covered by the scripts above, links the same DH/crypto code):
```bash
chmod +x compileMitm
./compileMitm #produces mitm.exe
```

## Run — Normal Flow

Server VM:
```bash
./server.exe
```

Each Client VM:
```bash
./client.exe <SERVER_IP> 5000
```

Both sides print a fingerprint of the derived AES key on connect — check the client
and server logs to confirm they match.

## Run — MITM Attack

On the Mallory VM, point the proxy at the real server:
```bash
./mitm.exe <SERVER_IP> 5000
```
This listens on port 5001 and forwards to the real server.

On a Client VM, connect to Mallory instead of the real server:
```bash
./client.exe <MALLORY_IP> 5001
```

Chat normally between C1 and C2. Check Mallory's console log — it should show every
message in plaintext, and both client and server fingerprints will still match their
respective (separate) DH exchanges with Mallory, even though the client believes it's
talking directly to the server.

## Tamper Detection Test

```bash
g++ -std=c++17 src/tests/test_tamper.cpp src/crypto/crypto.cpp -o test_tamper.exe -lcrypto

./test_tamper.exe
```
This flips a bit in a captured ciphertext and confirms AES-GCM rejects it instead of
decrypting to garbage.

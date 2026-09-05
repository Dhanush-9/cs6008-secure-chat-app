# Phase 1 — Baseline Chat Application (No Security)

A one-to-one/multi-client TCP chat app. No encryption this phase just proves the
basic protocol, framing, and routing work.

## Files in This Phase

- `protocol.cpp` / `protocol.hpp` — message struct, LOGIN/MSG/WHO/QUIT/OK/ERROR/USERS/FROM parsing
- `framing.cpp` / `framing.hpp` — length-prefixed message framing over TCP
- `server.cpp` — the chat server
- `client.cpp` — the chat client

## VM Topology

Three VMs, each with two network adapters:
- **NAT adapter** — internet access (for `apt install`, etc.)
- **Host-only adapter** — a private LAN so the VMs can talk to each other

| VM | Role | Host-only IP |
|---|---|---|
| Server VM | S | `192.168.56.102` |
| Client1 VM | C1 | `192.168.56.101` |
| Client2 VM | C2 | `192.168.56.103` |

Before running anything, confirm the VMs can see each other:
```bash
ping <SERVER_IP>   # from C1 and C2
```

## Dependencies

None beyond a C++ compiler — Phase 1 has no crypto.

```bash
sudo apt update
sudo apt install g++ make
```

## Build

```bash
cd phase1/

#compile server
g++ -std=c++17 -pthread src/server.cpp src/protocol.cpp src/framing.cpp -I include/ -o server.exe

#compile client
g++ -std=c++17 -pthread src/client.cpp src/protocol.cpp src/framing.cpp -I include/ -o client.exe
```

## Run

On the Server VM:
```bash
./server.exe
```
Server starts listening on port 5000.

On each Client VM:
```bash
./client.exe <SERVER_IP> 5000
```

Then log in and chat:
```
> login Alice
> /who
> /chat Bob
> @Bob Hello!
> /quit
```

#pragma once

#include<string>

enum class MessageType {
    LOGIN,
    MSG,
    WHO,
    QUIT,
    OK,
    ERROR,
    USERS,
    FROM,
    DH_HELLO,
    // Phase 4: client-to-client end-to-end encryption handshake & messaging
    // E2E_INIT,   // initiator sends its DH public key to a peer via server relay
    // E2E_REPLY,  // responder sends its DH public key back via server relay
};

const char SEPARATOR = '|';

struct Message{
    MessageType type;
    std::string sender;
    std::string receiver;
    std::string content;
};

bool parse_message(const std::string& payload, Message& message);

std::string serialize_message(const Message& message);


/*
------------------------
    MESSAGE FRAMING
------------------------

Every payload is transmitted using length-prefixed frame:

[length][payload]

where length is fixed 4-bytes unsigned int 
and represents no. of bytes in payload

The receiver would read the 4-byte length first 
and then read exactly that many payload bytes.

------------------------
PROTOCOL MESSAGE FORMATS
------------------------

Client -> Server

1) LOGIN

LOGIN|<username>
Client requests to login using username.

2) MSG

MSG|<receiver>|<message>
Client sends a message to receiver.

3) WHO

WHO
Client requests list of currently online users.

4) QUIT

QUIT
Client closes session.

--- Phase 4: E2E handshake & encrypted chat (relayed by server) ---

5) E2E_INIT  (carried inside MSG|<receiver>|E2E_INIT|<pubkey_hex>)

Client C1 sends its DH public key to C2 to begin a client-to-client key exchange.
The server forwards this as a FROM message; it never derives or stores the E2E key.

6) E2E_REPLY  (carried inside MSG|<receiver>|E2E_REPLY|<pubkey_hex>)

Client C2 responds with its own DH public key so C1 can complete the handshake.

7) E2E_MSG  (carried inside MSG|<receiver>|E2E_MSG|<hex_ciphertext>)

An inner AES-GCM ciphertext (hex-encoded) encrypted with the C1<->C2 shared key.
The server relays the opaque hex blob without being able to read it.


Server -> Client

1) OK

OK|<operation>
Server confirms that operation was successful.

2) ERROR

ERROR|<reason>
Server returns error with the reason.

3) USERS

USERS|<username1>|<username2>|...
Server returns the list of currently online users.

4) FROM

FROM|<sender>|<message>  
Server delivers message to the receiver.
The <message> field may be prefixed with E2E_INIT|, E2E_REPLY|, or E2E_MSG|
when relaying phase-4 handshake/encrypted traffic.
*/
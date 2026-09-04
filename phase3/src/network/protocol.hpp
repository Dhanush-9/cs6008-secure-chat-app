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

    CERT,
    CHALLENGE,
    CHALLENGE_RESP
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
and represnt no. of bytes in payload

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
*/
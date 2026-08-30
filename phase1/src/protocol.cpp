#include "protocol.hpp"
#include<string>

bool parse_message(const std::string& payload, Message& message) {
    // QUIT
    if(payload == "QUIT"){
        message.type = MessageType::QUIT;
        return true;
    }

    // WHO
    if(payload == "WHO"){
        message.type = MessageType::WHO;
        return true;
    }

    size_t position = payload.find("|");
    if(position == std::string::npos){
        return false;
    }

    std::string type = payload.substr(0, position);

    // OK|<operation>
    // ERROR|<reason>
    if(type == "OK" || type == "ERROR"){
        std::string content = payload.substr(position + 1);

        if(content.empty()){
            return false;
        }

        message.content = content;

        if(type == "OK"){
            message.type = MessageType::OK;
        }
        else{
            message.type = MessageType::ERROR;
        }

        return true;
    }

    // LOGIN|<username>
    if(type == "LOGIN"){
        message.type = MessageType::LOGIN;
        std::string username = payload.substr(position + 1);

        if(username.empty()){
            return false;
        }

        message.sender = username;
        return true;
    }

    // MSG|<receiver>|<message>
    if(type == "MSG"){
        size_t next_pos = payload.find("|", position + 1);
        if(next_pos == std::string::npos){
            return false;
        }

        std::string receiver = payload.substr(position + 1, next_pos - position - 1);

        std::string content = payload.substr(next_pos + 1);

        if(receiver.empty() || content.empty()){
            return false;
        }

        message.type = MessageType::MSG;
        message.receiver = receiver;
        message.content = content;

        return true;
    }

    //FROM|<sender>|<message>
    if(type == "FROM"){
        size_t next_pos = payload.find("|", position + 1);
        if(next_pos == std::string::npos){
            return false;
        }

        std::string sender = payload.substr(position + 1, next_pos - position - 1);

        std::string content = payload.substr(next_pos + 1);

        if(sender.empty() || content.empty()){
            return false;
        }

        message.type = MessageType::FROM;
        message.sender = sender;
        message.content = content;

        return true;
    }

    //USERS|<username1>|<username2>|...
    if(type == "USERS"){
        std::string users = payload.substr(position + 1);

        if(users.empty()){
            return false;
        }

        message.type = MessageType::USERS;
        message.content = users;

        return true;
    }

    return false;
}

std::string serialize_message(const Message& message){

    if(message.type == MessageType::LOGIN){
        return "LOGIN|" + message.sender;
    }

    if(message.type == MessageType::MSG){
        return "MSG|" + message.receiver + "|" + message.content;
    }

    if(message.type == MessageType::WHO){
        return "WHO";
    }

    if(message.type == MessageType::QUIT){
        return "QUIT";
    }

    if(message.type == MessageType::OK){
        return "OK|" + message.content;
    }

    if(message.type == MessageType::ERROR){
        return "ERROR|" + message.content;
    }

    if(message.type == MessageType::USERS){
        return "USERS|" + message.content;
    }

    if(message.type == MessageType::FROM){
        return "FROM|" + message.sender + "|" + message.content;
    }

    return "";
}
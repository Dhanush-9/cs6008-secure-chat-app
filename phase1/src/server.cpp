#include "protocol.hpp"
#include "framing.hpp"
#include "client_registry.hpp"

#include <iostream>
#include <string>
#include <thread>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

const int PORT = 5000;

bool handle_message(int client_fd, std::string& username, Message& message, ClientRegistry& registry){
    if(message.type == MessageType::WHO){
        std::vector<std::string> users = registry.get_users();

        std::string who_content;

        for(auto user : users){
            if(!who_content.empty()){
                who_content += "|";
            }

            who_content += user;
        }

        Message response;
        response.type = MessageType::USERS;
        response.content = who_content;

        send_frame(client_fd, serialize_message(response));
        return true;
    }

    if(message.type == MessageType::MSG){
        int receiver_fd = registry.get_socket(message.receiver);

        if(receiver_fd < 0){
            Message response;

            response.type = MessageType::ERROR;
            response.content = "User not found";

            send_frame(client_fd, serialize_message(response));

            return true;
        }

        Message outgoing;

        outgoing.type = MessageType::FROM;
        outgoing.sender = username;
        outgoing.content = message.content;

        std::cout << "Message Log: FROM ["
          << username << "] TO ["
          << message.receiver << "]: "
          << message.content << "\n";

        //situation where this fails?
        send_frame(receiver_fd, serialize_message(outgoing));

        return true;
    }

    if(message.type == MessageType::QUIT){
        return false;
    }

    return true;
}

void handle_client(int client_fd, ClientRegistry& registry){
    std::string payload;

    if(receive_frame(client_fd, payload) == false){
        close(client_fd);
        return;
    }

    Message message;

    if(parse_message(payload, message) == false){
        Message response;

        response.type = MessageType::ERROR;
        response.content = "Invalid message";

        send_frame(client_fd, serialize_message(response));
        close(client_fd);
        return;
    }

    if(message.type != MessageType::LOGIN){
        Message response;

        response.type = MessageType::ERROR;
        response.content = "Login required";

        send_frame(client_fd, serialize_message(response));
        close(client_fd);
        return;
    }

    //message is LOGIN, register the client
    std::string username = message.sender;

    if(registry.add_client(username, client_fd) == false){
        //username exists already
        Message response;
        response.type = MessageType::ERROR;

        response.content = "Username already exists";
        std::string response_payload = serialize_message(response);

        send_frame(client_fd, response_payload);

        close(client_fd);
        return;
    }

    //logged in successfully
    Message response;

    response.type = MessageType::OK;
    response.content = "Login successful";

    send_frame(client_fd, serialize_message(response));

    std::cout << "Client \"" << username << "\" logged in.\n";

    while(true){
        std::string payload;

        if(receive_frame(client_fd, payload) == false){
            break;
        }

        Message message;

        if(parse_message(payload, message) == false){
            Message response;

            response.type = MessageType::ERROR;
            response.content = "Invalid message";

            send_frame(client_fd, serialize_message(response));
            continue;
        }

        if(handle_message(client_fd, username, message, registry) == false){
            break;
        }
    }

    registry.remove_client(username);
    close(client_fd);

    std::cout << "Client \"" << username << "\" disconnected.\n";
}

int main(){

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);

    if(server_fd < 0){
        std::cerr << "Socket Failed\n";
        return 1;
    }

    sockaddr_in server_addr{}, client_addr{};

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    //binding
    if(bind(server_fd, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) < 0){
        std::cerr << "Bind Failed\n";
        close(server_fd);
        return 1;
    }

    if(listen(server_fd, 5) < 0){
        std::cerr << "Listen Failed\n";
        close(server_fd);
        return 1;
    }

    std::cout << "Server started and listening on port " << PORT << "...\n";

    ClientRegistry registry;

    while(true){
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, reinterpret_cast<sockaddr*> (&client_addr), &client_len);

        if(client_fd < 0){
            std::cerr << "Accept Failed\n";
            continue;
        }

        std::thread client_thread(handle_client, client_fd, std::ref(registry));
        client_thread.detach();
    }

    close(server_fd);

    return 0;
}
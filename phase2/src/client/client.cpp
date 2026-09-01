#include "protocol.hpp"
#include "framing.hpp"

#include <iostream>
#include <string>
#include <thread>
#include <sstream>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

const char *SERVER_IP = "127.0.0.1";
const int PORT = 5000;

void receive_messages(int sock_fd){
    while(true){
        std::string payload;

        if(receive_frame(sock_fd, payload) == false){
            break;
        }

        Message message;

        if(parse_message(payload, message) == false){
            std::cerr << "\nERROR: Invalid message from server.\n";
            continue;
        }

        if(message.type == MessageType::FROM){
            std::cout << "\n[" << message.sender << "]" << message.content << "\n";
            std::cout << "> ";
            std::flush(std::cout);
        }

        if(message.type == MessageType::USERS){
            std::stringstream ss(message.content);
            std::string user;

            std::cout << "\nOnline Users:\n";

            while(std::getline(ss, user, '|')){
                std::cout << " " << user << "\n";
            }

            std::cout << "> ";
            std::flush(std::cout);
        }

        if(message.type == MessageType::ERROR){
            std::cout << "ERROR: " << message.content << "\n";

            std::cout << "> ";
            std::flush(std::cout);
        }

        if(message.type == MessageType::OK){
            std::cout << "\n" << message.content << "\n";

            std::cout << "> ";
            std::flush(std::cout);
        }
    }
}

int main()
{
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (sock_fd < 0)
    {
        std::cerr << "Socket failed\n";
        return 1;
    }

    sockaddr_in server_addr{};

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);

    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    if (connect(sock_fd, reinterpret_cast<sockaddr *>(&server_addr), sizeof(server_addr)) < 0)
    {
        std::cerr << "Connect failed\n";
        close(sock_fd);
        return 1;
    }

    std::cout << "Connection to server established.\n";

    std::cout << "\nLogin first.\n";
    std::cout << "Usage: login <username>\n\n";

    bool logged_in = false;

    while (!logged_in)
    {
        std::cout << "> ";

        std::string input;
        std::getline(std::cin, input);

        std::stringstream ss(input);

        std::string command;
        std::string username;

        ss >> command;
        ss >> username;

        if (command != "login" || username.empty())
        {
            std::cout << "ERROR: Login first.\n";
            std::cout << "Usage: login <username>\n";
            continue;
        }

        Message login;
        login.type = MessageType::LOGIN;
        login.sender = username;

        if (send_frame(sock_fd, serialize_message(login)) == false)
        {
            std::cerr << "Failed to Login.\n";
            close(sock_fd);
            return 1;
        }

        std::string response_payload;
        if (receive_frame(sock_fd, response_payload) == false)
        {
            std::cerr << "Server disconnected.\n";
            close(sock_fd);
            return 1;
        }

        Message response;

        if (parse_message(response_payload, response) == false)
        {
            std::cerr << "Invalid response from Server.\n";
            close(sock_fd);
            return 1;
        }

        if (response.type == MessageType::OK)
        {
            std::cout << response.content << "\n";
            logged_in = true;
        }
        else if (response.type == MessageType::ERROR)
        {
            std::cout << "ERROR: " << response.content << "\n";
        }
    }

    std::thread receiver_thread(receive_messages, sock_fd);
    receiver_thread.detach();

    std::string current_chat;

    std::cout << "> ";

    while (true)
    {
        std::string input;
        std::getline(std::cin, input);

        std::stringstream ss(input);

        if(input.empty()){
            std::cout << "> ";
            continue;
        }

        std::string command;
        std::string argument;

        ss >> command;
        ss >> argument;

        if(command == "/who"){
            Message message;

            message.type = MessageType::WHO;

            send_frame(sock_fd, serialize_message(message));
        }

        else if(command == "/chat"){
            if(argument.empty()){
                std::cout << "Usage: /chat <username>\n";
                continue;
            }

            current_chat = argument;

            std::cout << "Current chat: " << current_chat << "\n";

            std::cout << "> ";
            std::flush(std::cout);
        }

        else if(command == "/quit"){
            Message message;

            message.type = MessageType::QUIT;

            send_frame(sock_fd, serialize_message(message));

            close(sock_fd);
            return 0;
        }

        else if(input[0] == '@'){
            std::stringstream ss(input.substr(1));

            std::string username;
            std::string content;

            ss >> username;

            std::getline(ss, content);

            if(!content.empty() && content[0] == ' '){
                content.erase(0, 1);
            }

            if(username.empty() || content.empty()){
                std::cout << "usage: @username <message>\n";
                continue;
            }

            Message message;

            message.type = MessageType::MSG;
            message.receiver = username;
            message.content = content;

            if(send_frame(sock_fd, serialize_message(message)) == false){
                std::cerr << "Failed to send message.\n";
                close(sock_fd);
                return 1;
            }

            current_chat = username;

            std::cout << "> ";
            std::flush(std::cout);
        }

        else{
            if(current_chat.empty()){
                std::cout << "No receiver selected.\n";
                std::cout << "Use: /chat <username>\n";
                continue;
            }

            Message message;

            message.type = MessageType::MSG;
            message.receiver = current_chat;
            message.content = input;

            if(send_frame(sock_fd, serialize_message(message)) == false){
                std::cerr << "Failed to send message.\n";
                close(sock_fd);
                return 1;
            }

            std::cout << "> ";
            std::flush(std::cout);
        }
    }
}
#include "../network/protocol.hpp"
#include "../network/framing.hpp"
#include "../crypto/dh.hpp"
#include "../crypto/crypto.hpp"

#include <iostream>
#include <string>
#include <thread>
#include <sstream>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <vector>
#include <cstdint>

void receive_messages(int sock_fd, const std::vector<uint8_t>& aes_key) {
    while(true){
        std::string payload;

        // if(receive_frame(sock_fd, payload) == false){
        //     break;
        // } //plain msg
        if(!receive_frame_enc(sock_fd, payload, aes_key)){
            std::cerr << "\n[Connection closed or tamper detected — exiting receiver]\n";
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

int main(int argc, char *argv[])
{

    if(argc != 3){
        std::cerr << "Usage: "<< argv[0] << " <server_ip> <port>\n";
        return 1;
    }

    char *SERVER_IP = argv[1];
    int PORT = std::atoi(argv[2]);

    if(PORT <= 0 || PORT > 65535){
        std::cerr << "Invalid port: " << argv[2] << "\n";
        return 1;
    }

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

    //DH Handshake
    DHkeypair dh = dh_generate_keypair();

    //Send client's public key to server
    Message dh_hello;
    dh_hello.type = MessageType::DH_HELLO;
    dh_hello.content = BignumUniquePtrToHexString(dh.public_key);

    if(!send_frame(sock_fd, serialize_message(dh_hello))){
        std::cerr << "Failed to send DH hello.\n";
        close(sock_fd);
        return 1;
    }

    //Receive the server's public key
    std::string serverDHHelloPayload;
    if(!receive_frame(sock_fd, serverDHHelloPayload)){
        std::cerr << "Failed to receive server's public key.\n";
        close(sock_fd);
        return 1;
    }

    Message serverPublicKeyMsg;
    if(parse_message(serverDHHelloPayload, serverPublicKeyMsg) == false){
        std::cerr << "Invalid message from server.\n";
        close(sock_fd);
        return 1;
    }

    // //Generate shared secret
    // BignumUniquePtr sharedSecret = dhGetSecret(dh, serverPublicKeyMsg.content);

    // //Generate AES key
    // std::vector<uint8_t> aes_key = deriveAesKey(sharedSecret);

    BignumUniquePtr serverPubKey = customHexToBignumUniquePtr(serverPublicKeyMsg.content);
    std::vector<uint8_t> sharedSecret = dhGetSecret(dh, serverPubKey);
    std::vector<uint8_t> aes_key = deriveAesKey(sharedSecret);

    //Print FingerPrint
    print_fingerprint(aes_key);

    std::cout << "DH handshake complete. Secure channel established. All further communication is encrypted.\n\n";

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

        // if (send_frame(sock_fd, serialize_message(login)) == false)
        // {
        //     std::cerr << "Failed to Login.\n";
        //     close(sock_fd);
        //     return 1;
        // }
        if (!send_frame_enc(sock_fd, serialize_message(login), aes_key))
        {
            std::cerr << "Failed to Login.\n";
            close(sock_fd);
            return 1;
        }

        std::string response_payload;
        // if (receive_frame(sock_fd, response_payload) == false)
        // {
        //     std::cerr << "Server disconnected.\n";
        //     close(sock_fd);
        //     return 1;
        // }
        if (!receive_frame_enc(sock_fd, response_payload, aes_key))
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

    std::thread receiver_thread(receive_messages, sock_fd, aes_key);
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

            send_frame_enc(sock_fd, serialize_message(message), aes_key);
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

            send_frame_enc(sock_fd, serialize_message(message), aes_key);

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

            if(send_frame_enc(sock_fd, serialize_message(message), aes_key) == false){
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

            if(send_frame_enc(sock_fd, serialize_message(message), aes_key) == false){
                std::cerr << "Failed to send message.\n";
                close(sock_fd);
                return 1;
            }

            std::cout << "> ";
            std::flush(std::cout);
        }
    }
}
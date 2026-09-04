#include "../network/protocol.hpp"
#include "../network/framing.hpp"
#include "../crypto/dh.hpp"
#include "../crypto/crypto.hpp"
#include "../crypto/server_auth.hpp"
#include "client_registry.hpp"

#include <iostream>
#include <string>
#include <thread>
#include <fstream>
#include <sstream>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

const int PORT = 5000;

bool handle_message(int client_fd,
                    std::string& username,
                    Message& message,
                    ClientRegistry& registry,
                    const std::vector<uint8_t>& aes_key)
{
    if(message.type == MessageType::WHO){
        std::vector<std::string> users = registry.get_users();

        std::string who_content;
        for(auto user : users){
            if(!who_content.empty()) who_content += "|";
            who_content += user;
        }

        Message response;
        response.type    = MessageType::USERS;
        response.content = who_content;

        send_frame_enc(client_fd, serialize_message(response), aes_key);
        return true;
    }

    if(message.type == MessageType::MSG){

        int receiver_fd = registry.get_socket(message.receiver);
        if(receiver_fd < 0){
            Message response;
            response.type    = MessageType::ERROR;
            response.content = "User not found";
            send_frame_enc(client_fd, serialize_message(response), aes_key);
            return true;
        }

        std::vector<uint8_t> receiverKey = registry.get_key(message.receiver);

        Message outgoing;
        outgoing.type    = MessageType::FROM;
        outgoing.sender  = username;
        outgoing.content = message.content;

        std::cout << "Message Log: FROM ["
          << username << "] TO ["
          << message.receiver << "]: "
          << message.content << "\n";

        send_frame_enc(receiver_fd, serialize_message(outgoing), receiverKey);
        return true;
    }

    if(message.type == MessageType::QUIT){
        return false;
    }

    return true;
}

std::string read_file(const std:: string& path){
    std::ifstream file(path);

    if(!file) return "";

    std::stringstream buffer;
    buffer << file.rdbuf();

    return buffer.str();
}

void handle_client(int client_fd, ClientRegistry& registry){

    // PHASE 3: Server Authentication

    //load server certificate
    std::string server_cert = read_file("src/server/server.crt");

    if(server_cert.empty()) {
        std::cerr << "Failed to load server certificate\n";
        close(client_fd);
        return;
    }

    //load server private key
    std::string server_private_key = read_file("src/server/server.key");

    if(server_private_key.empty()) {
        std::cerr << "Failed to load server private key\n";
        close(client_fd);
        return;
    }

    //send server.crt to client
    Message cert_message;

    cert_message.type = MessageType::CERT;
    cert_message.content = server_cert;

    if(send_frame(client_fd, serialize_message(cert_message)) == false){
        std::cerr << "Failed to send server certificate\n";
        close(client_fd);
        return;
    }

    std::cout<<"Server certificate successfully sent to Client.\n";

    //recieve challenge from client
    std::string challenge_payload;

    if(receive_frame(client_fd, challenge_payload) == false){
        std::cerr << "Failed to receive challenge\n";
        close(client_fd);
        return;
    }

    Message challenge_message;
    if(parse_message(challenge_payload, challenge_message) == false){
        std::cerr << "Failed to parse challenge message\n";
        close(client_fd);
        return;
    }

    if (challenge_message.type != MessageType::CHALLENGE) {
        std::cerr << "Expected CHALLENGE message\n";
        close(client_fd);
        return;
    }

    //sign challenge using server's private key
    std::string signature = sign_challenge(challenge_message.content, server_private_key);

    if (signature.empty()) {
        std::cerr << "Failed to sign challenge\n";
        close(client_fd);
        return;
    }

    //send challenge response
    Message challenge_response;

    challenge_response.type = MessageType::CHALLENGE_RESP;
    challenge_response.content = signature;

    if(send_frame(client_fd, serialize_message(challenge_response)) == false){
        std::cerr << "Failed to send challenge response\n";
        close(client_fd);
        return;
    }

    std::cout << "Signed the challenge and successfully sent the response.\n";


    std::cout << "Server authentication complete.\n";

    // DH Handshake with Client (establishes client<->server channel key)
    DHkeypair dh = dh_generate_keypair();

    std::string clientPubKeyPayload;
    if(receive_frame(client_fd, clientPubKeyPayload) == false){
        std::cerr << "Failed to receive client's public key\n";
        close(client_fd);
        return;
    }

    Message clientPubKeyMessage;
    if(parse_message(clientPubKeyPayload, clientPubKeyMessage) == false){
        std::cerr << "Failed to parse client's public key message\n";
        close(client_fd);
        return;
    }

    if(clientPubKeyMessage.type != MessageType::DH_HELLO){
        std::cerr << "Expected DH_HELLO message, but received a different type\n";
        close(client_fd);
        return;
    }

    BignumUniquePtr clientPubKey = customHexToBignumUniquePtr(clientPubKeyMessage.content);
    if(!clientPubKey){
        std::cerr << "Failed to convert client's public key from hex to BIGNUM\n";
        close(client_fd);
        return;
    }

    // Send server's public key
    Message serverPubKeyMessage;
    serverPubKeyMessage.type    = MessageType::DH_HELLO;
    serverPubKeyMessage.content = BignumUniquePtrToHexString(dh.public_key);

    if(send_frame(client_fd, serialize_message(serverPubKeyMessage)) == false){
        std::cerr << "Failed to send server's public key\n";
        close(client_fd);
        return;
    }

    // Derive client<->server channel key (NOT the E2E key)
    std::vector<uint8_t> sharedSecret = dhGetSecret(dh, clientPubKey);
    std::vector<uint8_t> aes_key      = deriveAesKey(sharedSecret);

    print_fingerprint(aes_key, "Server (fd=" + std::to_string(client_fd) + ") [client-server key]");

    std::string payload;
    if(receive_frame_enc(client_fd, payload, aes_key) == false){
        close(client_fd);
        return;
    }

    Message message;
    if(parse_message(payload, message) == false){
        Message response;
        response.type    = MessageType::ERROR;
        response.content = "Invalid message";
        send_frame_enc(client_fd, serialize_message(response), aes_key);
        close(client_fd);
        return;
    }

    if(message.type != MessageType::LOGIN){
        Message response;
        response.type    = MessageType::ERROR;
        response.content = "Login required";
        send_frame_enc(client_fd, serialize_message(response), aes_key);
        close(client_fd);
        return;
    }

    std::string username = message.sender;

    if(registry.add_client(username, client_fd, aes_key) == false){
        Message response;
        response.type    = MessageType::ERROR;
        response.content = "Username already exists";
        send_frame_enc(client_fd, serialize_message(response), aes_key);
        close(client_fd);
        return;
    }

    Message response;
    response.type    = MessageType::OK;
    response.content = "Login successful";
    send_frame_enc(client_fd, serialize_message(response), aes_key);

    std::cout << "Client \"" << username << "\" logged in.\n";

    while(true){
        std::string payload;

        if(receive_frame_enc(client_fd, payload, aes_key) == false){
            break;
        }

        Message message;

        if(parse_message(payload, message) == false){
            Message response;
            response.type    = MessageType::ERROR;
            response.content = "Invalid message";
            send_frame_enc(client_fd, serialize_message(response), aes_key);
            continue;
        }

        if(handle_message(client_fd, username, message, registry, aes_key) == false){
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

    server_addr.sin_family      = AF_INET;
    server_addr.sin_port        = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

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
        int client_fd = accept(server_fd,
                               reinterpret_cast<sockaddr*>(&client_addr),
                               &client_len);

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

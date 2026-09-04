#include "../network/protocol.hpp"
#include "../network/framing.hpp"
#include "../crypto/dh.hpp"
#include "../crypto/crypto.hpp"
#include "client_registry.hpp"

#include <iostream>
#include <string>
#include <thread>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

const int PORT = 5000;

// ---------------------------------------------------------------------------
// Utility: log what the server is relaying.
// For E2E_MSG the content is opaque hex — this makes the opacity visible.
// For plain MSG it shows readable plaintext (pre-E2E contrast evidence).
// ---------------------------------------------------------------------------
static void log_relay(const std::string& tag,
                      const std::string& from_user,
                      const std::string& to_user,
                      const std::string& content)
{
    std::string preview = content.substr(0, 64);
    if(content.size() > 64) preview += "...";

    std::cout << "[RELAY] type=" << tag
              << " from="        << from_user
              << " to="          << to_user
              << " content=\""   << preview << "\"\n";
    std::cout.flush();
}

// ---------------------------------------------------------------------------
// Forward an E2E handshake/data frame to the destination client.
// The server wraps it in a FROM and forwards the opaque blob — it never sees
// the C1<->C2 key and cannot decrypt the inner payload.
// ---------------------------------------------------------------------------
static bool relay_e2e(int src_fd,
                      const std::string& src_user,
                      const std::string& tag,
                      const Message& message,
                      ClientRegistry& registry,
                      const std::vector<uint8_t>& src_key)
{
    int dst_fd = registry.get_socket(message.receiver);
    if(dst_fd < 0){
        Message err;
        err.type    = MessageType::ERROR;
        err.content = "User '" + message.receiver + "' not found";
        send_frame_enc(src_fd, serialize_message(err), src_key);
        return true;
    }

    std::vector<uint8_t> dst_key = registry.get_key(message.receiver);

    // FROM|<sender>|<tag>|<content>  — receiver's FROM handler picks up the tag prefix
    Message outgoing;
    outgoing.type    = MessageType::FROM;
    outgoing.sender  = src_user;
    outgoing.content = tag + "|" + message.content;

    log_relay(tag, src_user, message.receiver, message.content);

    send_frame_enc(dst_fd, serialize_message(outgoing), dst_key);
    return true;
}

// ---------------------------------------------------------------------------
// Main per-client message dispatcher
// ---------------------------------------------------------------------------
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
        // Log plain-text relay — server CAN read this (pre-E2E evidence)
        log_relay("MSG", username, message.receiver, message.content);

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

        send_frame_enc(receiver_fd, serialize_message(outgoing), receiverKey);
        return true;
    }

    // -----------------------------------------------------------------------
    // Phase 4: relay E2E handshake and encrypted chat.
    // Server is a pure relay — it forwards opaque blobs and cannot derive
    // the C1<->C2 shared key.
    // -----------------------------------------------------------------------
    if(message.type == MessageType::E2E_INIT){
        return relay_e2e(client_fd, username, "E2E_INIT", message, registry, aes_key);
    }

    if(message.type == MessageType::E2E_REPLY){
        return relay_e2e(client_fd, username, "E2E_REPLY", message, registry, aes_key);
    }

    if(message.type == MessageType::E2E_MSG){
        return relay_e2e(client_fd, username, "E2E_MSG", message, registry, aes_key);
    }

    if(message.type == MessageType::QUIT){
        return false;
    }

    return true;
}

// ---------------------------------------------------------------------------
// Per-client connection handler
// ---------------------------------------------------------------------------
void handle_client(int client_fd, ClientRegistry& registry){

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

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
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

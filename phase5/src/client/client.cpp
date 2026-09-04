#include "../network/protocol.hpp"
#include "../network/framing.hpp"
#include "../crypto/dh.hpp"
#include "../crypto/crypto.hpp"
#include "../crypto/server_auth.hpp"

#include <iostream>
#include <string>
#include <thread>
#include <fstream>
#include <sstream>
#include <map>
#include <mutex>
#include <iomanip>
#include <stdexcept>

#include <atomic> //for phase5
#include <chrono>
#include <ctime>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <vector>
#include <cstdint>

static std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for(uint8_t b : bytes)
        oss << std::setw(2) << (int)b;
    return oss.str();
}

static std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    if(hex.size() % 2 != 0)
        throw std::runtime_error("hex_to_bytes: odd-length hex string");
    std::vector<uint8_t> result;
    result.reserve(hex.size() / 2);
    for(size_t i = 0; i < hex.size(); i += 2){
        uint8_t byte = (uint8_t)std::stoi(hex.substr(i, 2), nullptr, 16);
        result.push_back(byte);
    }
    return result;
}

static std::string current_timestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&t));
    return std::string(buf);
}

struct E2EState {
    // username -> established E2E AES key
    std::map<std::string, std::vector<uint8_t>> aes_keys;
    // username -> pending DH keypair (awaiting E2E_REPLY)
    std::map<std::string, DHkeypair> pending;

    // std::string username;  //made for keeping track of only current user.
    // std::vector<uint8_t> aes_key;
    // DHkeypair dh;
    // bool e2e_established = false;
    std::atomic<bool> stop{false};
    std::mutex mtx;
};

void receive_messages(int sock_fd, const std::vector<uint8_t>& server_key, E2EState& e2e) {
    while(true){
        std::string payload;
        if(!receive_frame_enc(sock_fd, payload, server_key)){
            std::cerr << "\n[Connection closed or tamper detected — exiting receiver]\n";
            break;
        }

        Message message;
        if(!parse_message(payload, message)){
            std::cerr << "\nERROR: Invalid message from server.\n";
            std::cout << "> ";
            std::flush(std::cout);
            continue;
        }

        if(message.type == MessageType::FROM){
            const std::string& from    = message.sender;
            const std::string& content = message.content;

            // E2E_INIT: peer wants to establish an E2E session with us ---
            if(content.substr(0, 13) == "__E2E_INIT__|"){
                std::string peer_pub_hex = content.substr(13);

                // Generate our DH keypair
                DHkeypair our_dh = dh_generate_keypair();

                // Derive shared secret
                BignumUniquePtr peer_pub = customHexToBignumUniquePtr(peer_pub_hex);
                std::vector<uint8_t> secret = dhGetSecret(our_dh, peer_pub);
                std::vector<uint8_t> e2e_key = deriveAesKey(secret);

                {
                    std::lock_guard<std::mutex> lk(e2e.mtx);
                    // e2e.username = from;
                    // e2e.aes_key = e2e_key;
                    e2e.aes_keys[from] = e2e_key;
                }

                std::cout << "\n[E2E] Key-exchange initiated by " << from << ".\n";
                print_fingerprint(e2e_key, "[E2E with " + from + "] Fingerprint");
                std::cout << "[E2E] Secure session with " << from << " established!\n";
                std::cout << "> ";
                std::flush(std::cout);

                // Send our public key back as E2E_REPLY (relayed via server)
                Message reply;
                reply.type     = MessageType::MSG;
                reply.receiver = from;
                reply.content  = "__E2E_ACK__|" + BignumUniquePtrToHexString(our_dh.public_key);
                send_frame_enc(sock_fd, serialize_message(reply), server_key);

                //e2e.e2e_established = true;

                continue;
            }

            // E2E_REPLY: initiator receives responder's public key ---
            if(content.substr(0, 12) == "__E2E_ACK__|"){
                std::string peer_pub_hex = content.substr(12);

                std::lock_guard<std::mutex> lk(e2e.mtx);
                // auto it = e2e.pending.find(from);
                // if(it == e2e.pending.end()){
                //     std::cout << "\n[E2E] Unexpected E2E_REPLY from " << from << " (no pending handshake).\n";
                //     std::cout << "> ";
                //     std::flush(std::cout);
                //     continue;
                // }
                if(e2e.pending.find(from) == e2e.pending.end()){
                    std::cout << "\n[E2E] Unexpected E2E_REPLY from " << from << " (no pending handshake).\n";
                    std::cout << "> ";
                    std::flush(std::cout);
                    continue;
                }

                BignumUniquePtr peer_pub = customHexToBignumUniquePtr(peer_pub_hex);
                std::vector<uint8_t> secret  = dhGetSecret(e2e.pending[from], peer_pub);
                std::vector<uint8_t> e2e_key = deriveAesKey(secret);

                //e2e.aes_key = e2e_key;
                e2e.aes_keys[from] = e2e_key;
                e2e.pending.erase(from);
                //e2e.e2e_established = true;

                std::cout << "\n[E2E] Reply received from " << from << ".\n";
                print_fingerprint(e2e_key, "[E2E with " + from + "] Fingerprint");
                std::cout << "[E2E] Secure session with " << from << " established!\n";
                std::cout << "> ";
                std::flush(std::cout);
                continue;
            }

            // E2E_MSG: receive an inner-encrypted message ---
            if(content.substr(0, 12) == "__E2E_MSG__|"){
                std::string hex_blob = content.substr(12);

                std::vector<uint8_t> e2e_key;
                {
                    std::lock_guard<std::mutex> lk(e2e.mtx);
                    if(e2e.aes_keys.find(from) == e2e.aes_keys.end()){
                        std::cout << "\n[E2E] Received E2E_MSG from " << from
                                  << " but no session exists. Ignoring.\n";
                        std::cout << "> ";
                        std::flush(std::cout);
                        continue;
                    }
                    e2e_key = e2e.aes_keys[from];
                }

                try {
                    std::vector<uint8_t> ciphertext = hex_to_bytes(hex_blob);
                    std::vector<uint8_t> plaintext  = aes_gcm_decrypt(e2e_key, ciphertext);
                    std::string msg(plaintext.begin(), plaintext.end());

                    std::cout << "\n[E2E][" << from << "] " << msg << "\n";
                } catch(const std::exception& ex) {
                    std::cout << "\n[E2E] Decryption failed from " << from
                              << ": " << ex.what() << "\n";
                }

                std::cout << "> ";
                std::flush(std::cout);
                continue;
            }

            //Plain FROM message (no E2E) ---
            std::cout << "\n[" << from << "] " << content << "\n";
            std::cout << "> ";
            std::flush(std::cout);
            continue;
        }

        if(message.type == MessageType::USERS){
            std::stringstream ss(message.content);
            std::string user;
            std::cout << "\nOnline Users:\n";
            while(std::getline(ss, user, '|'))
                std::cout << "  " << user << "\n";
            std::cout << "> ";
            std::flush(std::cout);
            continue;
        }

        if(message.type == MessageType::ERROR){
            std::cout << "ERROR: " << message.content << "\n";
            std::cout << "> ";
            std::flush(std::cout);
            continue;
        }

        if(message.type == MessageType::OK){
            std::cout << "\n" << message.content << "\n";
            std::cout << "> ";
            std::flush(std::cout);
            continue;
        }
    }
}

void refresher_func(int sock_fd, const std::vector<uint8_t>& server_key, const std::string& my_username, E2EState& e2e){
    while(!e2e.stop) {
        // Sleep 60s in 100ms ticks so stop flag is checked frequently
        for(int i = 0; i < 600 && !e2e.stop; ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));

        if(e2e.stop) break;

        // Collect all peers we have an established E2E session with
        std::vector<std::string> peers;
        {
            std::lock_guard<std::mutex> lk(e2e.mtx);
            for(auto& kv : e2e.aes_keys)
                peers.push_back(kv.first);
        }

        for(const std::string& peer : peers) {
            if(my_username >= peer) continue; //prevents case where both client tries at same time.

            DHkeypair new_dh = dh_generate_keypair();
            std::string pub_hex = BignumUniquePtrToHexString(new_dh.public_key);
            {
                std::lock_guard<std::mutex> lk(e2e.mtx);
                e2e.pending[peer] = std::move(new_dh);
            }
            Message msg;
            msg.type     = MessageType::MSG;
            msg.receiver = peer;
            msg.content  = "__E2E_INIT__|" + pub_hex;
            send_frame_enc(sock_fd, serialize_message(msg), server_key);

            std::cout << "\n[REKEY] Sent refresh keys request to " << peer
                      << " at " << current_timestamp() << "\n> ";

            std::flush(std::cout);
        }
    }
}

std::string read_file(const std::string& path){
    std::ifstream file(path);

    if(!file){
        return "";
    }

    std::stringstream buffer;
    buffer << file.rdbuf();

    return buffer.str();
}

int main(int argc, char *argv[])
{

    if(argc != 3){
        std::cerr << "Usage: "<< argv[0] << " <server_ip> <port>\n";
        return 1;
    }

    char *SERVER_IP = argv[1];
    int PORT = std::atoi(argv[2]);


    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(sock_fd < 0){
        std::cerr << "Socket failed\n";
        return 1;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port   = htons(PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    if(connect(sock_fd, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) < 0){
        std::cerr << "Connect failed\n";
        close(sock_fd);
        return 1;
    }

    std::cout << "Connection to server established.\n";

    //Phase 3 Server Authentication
    std::string server_cert_payload;

    if(!receive_frame(sock_fd, server_cert_payload)){
        std::cerr << "Failed to receive server certificate.\n";
        close(sock_fd);
        return 1;
    }

    Message cert_message;

    if(!parse_message(server_cert_payload, cert_message)){
        std::cerr << "Invalid certificate message from server.\n";
        close(sock_fd);
        return 1;
    }

    if(cert_message.type != MessageType::CERT){
        std::cerr << "Expected server certificate.\n";
        close(sock_fd);
        return 1;
    }

    std::string server_certificate = cert_message.content;

    //read trusted CA certificate
    std::string ca_certificate = read_file("src/ca/ca.crt");

    if(ca_certificate.empty()){
        std::cerr << "Failed to read CA certificate.\n";
        close(sock_fd);
        return 1;
    }

    const std::string EXPECTED_SERVER_CN = "SecureChat Server";

    //validate server certificate
    if(!verify_server_certificate(server_certificate, ca_certificate, EXPECTED_SERVER_CN)){
        std::cerr << "Server certificate validation failed.\n";
        close(sock_fd);
        return 1;
    }

    std::cout << "Server certificate successfully validated.\n";

    //proof of possession

    std::string challenge = generate_challenge();

    Message challenge_message;

    challenge_message.type = MessageType::CHALLENGE;
    challenge_message.content = challenge;

    if(!send_frame(sock_fd, serialize_message(challenge_message))){
        std::cerr << "Failed to send challenge.\n";
        close(sock_fd);
        return 1;
    }

    //receive server's response

    std::string challenge_resp_payload;

    if(!receive_frame(sock_fd, challenge_resp_payload)){
        std::cerr << "Failed to receive challenge response.\n";
        close(sock_fd);
        return 1;
    }

    Message challenge_response;

    if(!parse_message(challenge_resp_payload, challenge_response)){
        std::cerr << "Invalid challenge response from server.\n";
        close(sock_fd);
        return 1;
    }

    if(challenge_response.type != MessageType::CHALLENGE_RESP){
        std::cerr << "Expected challenge response from server.\n";
        close(sock_fd);
        return 1;
    }

    if(!verify_challenge_response(challenge, challenge_response.content, server_certificate)){
        std::cerr << "Server proof-of-possession failed.\n";
        std::cerr << "Closing connection.\n";
        close(sock_fd);
        return 1;
    }

    std::cout << "proof-of-possession verified.\n";
    std::cout << "Server authentication complete.\n\n";

    DHkeypair dh = dh_generate_keypair();

    Message dh_hello;
    dh_hello.type    = MessageType::DH_HELLO;
    dh_hello.content = BignumUniquePtrToHexString(dh.public_key);

    if(!send_frame(sock_fd, serialize_message(dh_hello))){
        std::cerr << "Failed to send DH hello.\n";
        close(sock_fd);
        return 1;
    }

    std::string serverDHHelloPayload;
    if(!receive_frame(sock_fd, serverDHHelloPayload)){
        std::cerr << "Failed to receive server's public key.\n";
        close(sock_fd);
        return 1;
    }

    Message serverPublicKeyMsg;
    if(!parse_message(serverDHHelloPayload, serverPublicKeyMsg)){
        std::cerr << "Invalid message from server.\n";
        close(sock_fd);
        return 1;
    }

    BignumUniquePtr serverPubKey = customHexToBignumUniquePtr(serverPublicKeyMsg.content);
    std::vector<uint8_t> sharedSecret = dhGetSecret(dh, serverPubKey);
    std::vector<uint8_t> server_key   = deriveAesKey(sharedSecret);

    print_fingerprint(server_key, "[Client-Server key] Fingerprint");
    std::cout << "DH handshake complete. Secure channel established. All further communication is encrypted.\n\n";

    std::cout << "Login first.\nUsage: login <username>\n\n";

    std::string my_username;
    bool logged_in = false;

    while(!logged_in){
        std::cout << "> ";
        std::string input;
        std::getline(std::cin, input);

        std::stringstream ss(input);
        std::string command, username;
        ss >> command >> username;

        if(command != "login" || username.empty()){
            std::cout << "ERROR: Login first.\nUsage: login <username>\n";
            continue;
        }

        Message login;
        login.type   = MessageType::LOGIN;
        login.sender = username;

        if(!send_frame_enc(sock_fd, serialize_message(login), server_key)){
            std::cerr << "Failed to Login.\n";
            close(sock_fd);
            return 1;
        }

        std::string response_payload;
        if(!receive_frame_enc(sock_fd, response_payload, server_key)){
            std::cerr << "Server disconnected.\n";
            close(sock_fd);
            return 1;
        }

        Message response;
        if(!parse_message(response_payload, response)){
            std::cerr << "Invalid response from Server.\n";
            close(sock_fd);
            return 1;
        }

        if(response.type == MessageType::OK){
            std::cout << response.content << "\n";
            my_username = username;
            logged_in   = true;
        } else if(response.type == MessageType::ERROR){
            std::cout << "ERROR: " << response.content << "\n";
        }
    }

    E2EState e2e;
    e2e.aes_keys.clear();
    e2e.pending.clear();

    std::thread receiver_thread(receive_messages, sock_fd, std::cref(server_key), std::ref(e2e)); //ref is used because normally thread creates a copy of the argument, ref tells thread explicitly to use the reference of the argument instead of copying it.
    receiver_thread.detach();

    std::thread refresh_keys_60_seconds(refresher_func, sock_fd, std::cref(server_key), my_username, std::ref(e2e));
    refresh_keys_60_seconds.detach();

    std::string current_chat;
    std::cout << "> ";

    while(true){
        std::string input;
        std::getline(std::cin, input);
        bool directMessage = false;

        if(input.empty()){
            std::cout << "> ";
            continue;
        }

        std::stringstream ss(input);
        std::string command, argument;
        ss >> command >> argument;

        // /who — list online users
        if(command == "/who"){
            Message m;
            m.type = MessageType::WHO;
            send_frame_enc(sock_fd, serialize_message(m), server_key);
            continue;
        }

        // /chat <username> — set default chat target
        if(command == "/chat"){
            if(argument.empty()){
                std::cout << "Usage: /chat <username>\n";
                std::cout << "> ";
                continue;
            }
            current_chat = argument;
            std::cout << "Current chat: " << current_chat << "\n> ";
            std::flush(std::cout);

            // std::lock_guard<std::mutex> lk(e2e.mtx);
            // if(e2e.username != argument)
            // {
            //     e2e.aes_key.clear();
            //     e2e.e2e_established = false;
            //     e2e.username.clear();
            // }

            continue;
        }

        // /e2e <username> — initiate client-to-client DH key exchange
        if(command == "/e2e"){
            if(argument.empty()){
                std::cout << "Usage: /e2e <username>\n> ";
                std::flush(std::cout);
                continue;
            }

            std::string peer = argument;

            // Generate our DH keypair for this E2E session
            DHkeypair our_dh = dh_generate_keypair();
            std::string our_pub_hex = BignumUniquePtrToHexString(our_dh.public_key);

            {
                std::lock_guard<std::mutex> lk(e2e.mtx);
                e2e.pending.emplace(peer, std::move(our_dh));
                //e2e.dh = std::move(our_dh);
                //e2e.username = peer;
                //e2e.e2e_established = false;
            }

            // Send E2E_INIT to peer via server relay
            Message init_msg;
            init_msg.type     = MessageType::MSG; // relayed via server as a normal MSG
            init_msg.receiver = peer;
            init_msg.content  = "__E2E_INIT__|" + our_pub_hex;

            send_frame_enc(sock_fd, serialize_message(init_msg), server_key);

            std::cout << "[E2E] Handshake initiated with " << peer
                      << ". Waiting for reply...\n> ";
            std::flush(std::cout);
            continue;
        }

        // /quit
        if(command == "/quit"){
            Message m;
            m.type = MessageType::QUIT;
            send_frame_enc(sock_fd, serialize_message(m), server_key);
            e2e.stop = true;
            close(sock_fd);
            return 0;
        }

        // @username <message> — direct send (overrides current_chat)
        if(!input.empty() && input[0] == '@'){
            std::stringstream ss2(input.substr(1));
            std::string peer, msg_content;
            ss2 >> peer;
            std::getline(ss2, msg_content);
            if(!msg_content.empty() && msg_content[0] == ' ')
                msg_content.erase(0, 1);

            if(peer.empty() || msg_content.empty()){
                std::cout << "Usage: @username <message>\n> ";
                std::flush(std::cout);
                continue;
            }

            current_chat = peer;
            directMessage = true;
        }

        // Plain text input — send to current_chat
        if(current_chat.empty()){
            std::cout << "No receiver selected.\nUse: /chat <username>  or  @username <message>\n> ";
            std::flush(std::cout);
            continue;
        }

        // Check for active E2E session with current_chat peer
        std::vector<uint8_t> e2e_key;
        {
            std::lock_guard<std::mutex> lk(e2e.mtx);
            if(e2e.aes_keys.find(current_chat) != e2e.aes_keys.end()){
                e2e_key = e2e.aes_keys[current_chat];
            }
        }

        if(!e2e_key.empty()){
            // Inner AES-GCM encryption
            std::vector<uint8_t> plaintext(input.begin(), input.end());
            std::vector<uint8_t> ciphertext = aes_gcm_encrypt(e2e_key, plaintext);
            std::string hex_blob = bytes_to_hex(ciphertext);

            Message m;
            m.type     = MessageType::MSG;
            m.receiver = current_chat;
            m.content  = "__E2E_MSG__|" + hex_blob;

            std::cout << "[E2E] Sending encrypted message to " << current_chat << "\n";
            send_frame_enc(sock_fd, serialize_message(m), server_key);
        } else {
            // Plain message
            Message m;
            m.type     = MessageType::MSG;
            m.receiver = current_chat;
            if(directMessage) 
            {
                m.content = input.substr(input.find(' ')+1); // remove @username prefix
            }
            else 
            {
                m.content  = input;
            }

            if(!send_frame_enc(sock_fd, serialize_message(m), server_key)){
                std::cerr << "Failed to send message.\n";
                close(sock_fd);
                return 1;
            }
        }

        std::cout << "> ";
        std::flush(std::cout);
    }
}

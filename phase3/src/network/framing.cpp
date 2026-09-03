#include "framing.hpp"

#include<cstdint>
#include<sys/socket.h>
#include<arpa/inet.h>

bool send_all(int sock_fd, const char* data, size_t length){
    size_t bytes_remaining = length;

    while(bytes_remaining > 0){
        ssize_t bytes_sent = send(sock_fd, data, bytes_remaining, 0);

        if(bytes_sent == -1){
            return false;
        }

        //update offset
        data += bytes_sent;
        bytes_remaining -= bytes_sent;
    }

    return true;
}

bool recv_all(int sock_fd, char* data, size_t length){
    size_t bytes_remaining = length;

    while(bytes_remaining > 0){
        ssize_t bytes_received = recv(sock_fd, data, bytes_remaining, 0);

        if(bytes_received <= 0){
            return false;
        }

        //update offset
        data += bytes_received;
        bytes_remaining -= bytes_received;
    }

    return true;
}

bool send_frame(int sock_fd, const std::string& payload){
    //we want length to be fixed 4-bytes unsigned int
    uint32_t length = payload.size();

    uint32_t network_len = htonl(length);

    //send 4-byte prefixed length
    if(!send_all(sock_fd, reinterpret_cast<const char*>(&network_len), sizeof(network_len))){
        return false;
    }

    //send the payload
    if(!send_all(sock_fd, payload.c_str(), payload.size())){
        return false;
    }

    return true;
}

bool receive_frame(int sock_fd, std::string& payload){
    uint32_t network_len;

    //receive 4-byte prefixed length
    if(!recv_all(sock_fd, reinterpret_cast<char*>(&network_len), sizeof(network_len))){
        return false;
    }

    uint32_t length = ntohl(network_len);

    //allocate "length" space for payload
    payload.resize(length);

    //recieve the payload
    if(!recv_all(sock_fd, payload.data(), payload.size())){
        return false;
    }

    return true;
}

//Encrypted Send and Receive Frame

bool send_frame_enc(int sock_fd, const std::string& payload,
                    const std::vector<uint8_t>& key){
    // Convert string to bytes
    std::vector<uint8_t> plaintext(payload.begin(), payload.end());

    // Encrypt: result = [IV(12)] + [ciphertext] + [tag(16)]
    std::vector<uint8_t> encrypted = aes_gcm_encrypt(key, plaintext);

    // Send as a length-prefixed raw binary frame
    uint32_t length = static_cast<uint32_t>(encrypted.size());
    uint32_t network_len = htonl(length);

    if(!send_all(sock_fd, reinterpret_cast<const char*>(&network_len), sizeof(network_len))){
        return false;
    }

    if(!send_all(sock_fd, reinterpret_cast<const char*>(encrypted.data()), encrypted.size())){
        return false;
    }

    return true;
}

bool receive_frame_enc(int sock_fd, std::string& payload,
                       const std::vector<uint8_t>& key){
    // Read 4-byte length
    uint32_t network_len;
    if(!recv_all(sock_fd, reinterpret_cast<char*>(&network_len), sizeof(network_len))){
        return false;
    }

    uint32_t length = ntohl(network_len);

    // Read encrypted blob
    std::vector<uint8_t> encrypted(length);
    if(!recv_all(sock_fd, reinterpret_cast<char*>(encrypted.data()), length)){
        return false;
    }

    // Decrypt — throws std::runtime_error on GCM authentication failure
    try {
        std::vector<uint8_t> plaintext = aes_gcm_decrypt(key, encrypted);
        payload.assign(plaintext.begin(), plaintext.end());
    } catch (const std::exception& e) {
        std::cerr << "\n[SECURITY] Decryption failed: " << e.what() << "\n";
        std::cerr << "[SECURITY] Possible tampering detected — dropping message.\n";
        return false;
    }

    return true;
}
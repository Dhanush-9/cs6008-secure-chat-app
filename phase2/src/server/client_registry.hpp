#pragma once

#include <string>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <cstdint>

class ClientRegistry{

private:
    struct ClientInfo {
        int sock_fd;
        std::vector<uint8_t> aes_key;
    };
    std::unordered_map<std::string, ClientInfo> clients;
    mutable std::mutex mutex;

public:
    bool add_client(const std::string& username, int sock_fd, const std::vector<uint8_t>& aes_key);
    void remove_client(const std::string& username);

    bool has_client(const std::string& username) const;
    int get_socket(const std::string& username) const;

    std::vector<uint8_t> get_key(const std::string& username) const;

    std::vector<std::string> get_users() const;
};
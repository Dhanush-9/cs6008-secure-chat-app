#pragma once

#include <string>
#include <unordered_map>
#include <vector>
#include <mutex>

class ClientRegistry{

private:
    std::unordered_map<std::string, int> clients;
    mutable std::mutex mutex;

public:
    bool add_client(const std::string& username, int sock_fd);
    void remove_client(const std::string& username);

    bool has_client(const std::string& username) const;
    int get_socket(const std::string& username) const;

    std::vector<std::string> get_users() const;
};
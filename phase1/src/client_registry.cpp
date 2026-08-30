#include "client_registry.hpp"

bool ClientRegistry::add_client(const std::string& username, int sock_fd){
    std::lock_guard<std::mutex> lock(mutex);

    if(clients.find(username) != clients.end()){
        return false;
    }

    clients[username] = sock_fd;

    return true;
}

void ClientRegistry::remove_client(const std::string& username){
    std::lock_guard<std::mutex> lock(mutex);

    clients.erase(username);
}

bool ClientRegistry::has_client(const std::string& username) const{
    std::lock_guard<std::mutex> lock(mutex);

    return clients.find(username) != clients.end();
}

int ClientRegistry::get_socket(const std::string& username) const {
    std::lock_guard<std::mutex> lock(mutex);

    auto it = clients.find(username);

    return (it == clients.end())? -1 : it->second;
}

std::vector<std::string> ClientRegistry::get_users() const {
    std::lock_guard<std::mutex> lock(mutex);

    std::vector<std::string> users;

    for(auto client : clients){
        users.push_back(client.first);
    }

    return users;
}
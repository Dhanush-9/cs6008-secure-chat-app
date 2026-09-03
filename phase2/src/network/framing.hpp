#pragma once

#include<string>
#include<iostream>
#include<vector>
#include <cstdint>
#include "../crypto/crypto.hpp"

bool send_frame(int sock_fd, const std::string& payload);

bool receive_frame(int sock_fd, std::string& payload);

bool send_frame_enc(int sock_fd, const std::string& payload,
                    const std::vector<uint8_t>& key);

bool receive_frame_enc(int sock_fd, std::string& payload,
                       const std::vector<uint8_t>& key);
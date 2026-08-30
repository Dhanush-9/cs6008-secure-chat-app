#pragma once

#include<string>

bool send_frame(int sock_fd, const std::string& payload);

bool receive_frame(int sock_fd, std::string& payload);
#pragma once

#include <string>

bool verify_server_certificate(const std::string& certificate, const std::string& ca_certificate, const std::string& expected_cn);

std::string generate_challenge();

std::string sign_challenge(const std::string& challenge, const std::string& private_key);

bool verify_challenge_response(const std::string& challenge, const std::string& signature, const std::string& certificate);
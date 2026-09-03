#pragma once

#include <vector>
#include <string>
#include <cstdint>

std::vector<uint8_t> deriveAesKey(const std::vector<uint8_t>& secret);

void print_fingerprint(const std::vector<uint8_t>& aes_key, const std::string& label = "");

std::vector<uint8_t> aes_gcm_encrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& plaintext);

std::vector<uint8_t> aes_gcm_decrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data);
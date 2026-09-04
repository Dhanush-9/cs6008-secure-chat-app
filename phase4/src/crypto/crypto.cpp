#include "crypto.hpp"

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#include <stdexcept>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstring>

static const int AES_KEY_LEN = 16;  // AES-128
static const int GCM_IV_LEN  = 12;
static const int GCM_TAG_LEN = 16;

std::vector<uint8_t> deriveAesKey(const std::vector<uint8_t>& secret) {
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH); //SHA256_DIGEST_LENGTH = 32 defined in openssl/sha.h
    SHA256(secret.data(), secret.size(), hash.data());
    // Take first 16 bytes → AES-128 key
    return std::vector<uint8_t>(hash.begin(), hash.begin() + AES_KEY_LEN);
}

void print_fingerprint(const std::vector<uint8_t>& aes_key, const std::string& label) {
    std::vector<uint8_t> fingerprint(SHA256_DIGEST_LENGTH);
    SHA256(aes_key.data(), aes_key.size(), fingerprint.data());

    std::cout << label << " [Fingerprint] : ";
    for (uint8_t b : fingerprint) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    }
    std::cout << std::dec << "\n";
    std::cout.flush();
}

std::vector<uint8_t> aes_gcm_encrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& plaintext) {
    std::vector<uint8_t> iv(GCM_IV_LEN);
    if (RAND_bytes(iv.data(), GCM_IV_LEN) != 1)
        throw std::runtime_error("RAND_bytes failed");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    // Initialize AES-128-GCM encryption
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) != 1)
        throw std::runtime_error("EVP_EncryptInit_ex (cipher) failed");

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, nullptr) != 1)
        throw std::runtime_error("EVP_CIPHER_CTX_ctrl (IV len) failed");

    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1)
        throw std::runtime_error("EVP_EncryptInit_ex (key+iv) failed");

    // Encrypt plaintext
    std::vector<uint8_t> ciphertext(plaintext.size());
    int out_len = 0;

    if (!plaintext.empty()) {
        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len,
                              plaintext.data(), (int)plaintext.size()) != 1)
            throw std::runtime_error("EVP_EncryptUpdate failed");
    }

    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + out_len, &final_len) != 1)
        throw std::runtime_error("EVP_EncryptFinal_ex failed");

    // Retrieve GCM tag
    std::vector<uint8_t> tag(GCM_TAG_LEN);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag.data()) != 1)
        throw std::runtime_error("EVP_CIPHER_CTX_ctrl (get tag) failed");

    EVP_CIPHER_CTX_free(ctx);

    // Output layout: [IV (12)] [ciphertext] [tag (16)]
    std::vector<uint8_t> result;
    result.reserve(GCM_IV_LEN + ciphertext.size() + GCM_TAG_LEN);
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.begin() + out_len + final_len);
    result.insert(result.end(), tag.begin(), tag.end());

    return result;
}

std::vector<uint8_t> aes_gcm_decrypt(const std::vector<uint8_t>& key,
                                      const std::vector<uint8_t>& data) {
    if (key.size() != AES_KEY_LEN)
        throw std::runtime_error("Invalid AES key length");

    if (data.size() < (size_t)(GCM_IV_LEN + GCM_TAG_LEN))
        throw std::runtime_error("Ciphertext too short");

    // Parse: [IV (12)] [ciphertext] [tag (16)]
    const uint8_t* iv_ptr  = data.data();
    const uint8_t* ct_ptr  = data.data() + GCM_IV_LEN;
    size_t ct_len           = data.size() - GCM_IV_LEN - GCM_TAG_LEN;
    const uint8_t* tag_ptr = data.data() + GCM_IV_LEN + ct_len;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) != 1)
        throw std::runtime_error("EVP_DecryptInit_ex (cipher) failed");

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, nullptr) != 1)
        throw std::runtime_error("EVP_CIPHER_CTX_ctrl (IV len) failed");

    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv_ptr) != 1)
        throw std::runtime_error("EVP_DecryptInit_ex (key+iv) failed");

    // Decrypt ciphertext
    std::vector<uint8_t> plaintext(ct_len);
    int out_len = 0;

    if (ct_len > 0) {
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &out_len, ct_ptr, (int)ct_len) != 1)
            throw std::runtime_error("EVP_DecryptUpdate failed");
    }

    // Set the expected GCM tag before calling DecryptFinal
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN,
                             const_cast<uint8_t*>(tag_ptr)) != 1)
        throw std::runtime_error("EVP_CIPHER_CTX_ctrl (set tag) failed");

    // EVP_DecryptFinal_ex returns <= 0 if tag verification fails
    int final_len = 0;
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len, &final_len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) {
        // Tag mismatch — ciphertext has been tampered with
        throw std::runtime_error("GCM authentication failed: ciphertext has been tampered");
    }

    plaintext.resize(out_len + final_len);
    return plaintext;
}


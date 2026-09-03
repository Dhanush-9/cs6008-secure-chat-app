#include "../crypto/crypto.hpp"
#include <iostream>
#include <vector>

int main() {
    std::cout << "--- Testing AES-GCM Tamper Detection ---\n\n";

    // 1. Setup a test key and plaintext
    std::vector<uint8_t> key = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    std::string original_text = "LOGIN|alice";
    std::vector<uint8_t> plaintext(original_text.begin(), original_text.end());

    // 2. Encrypt
    std::vector<uint8_t> ciphertext = aes_gcm_encrypt(key, plaintext);
    std::cout << "Original ciphertext length: " << ciphertext.size() << " bytes\n";

    // 3. Verify clean decryption works first
    std::vector<uint8_t> decrypted = aes_gcm_decrypt(key, ciphertext);
    std::cout << "Clean decryption: " << std::string(decrypted.begin(), decrypted.end()) << " [OK]\n\n";

    // 4. TAMPER: Modify a single byte in the ciphertext body (e.g. byte 15)
    std::cout << ">>> Tampering: Flipping 1 bit in byte 15 of ciphertext...\n";
    std::vector<uint8_t> tampered_ciphertext = ciphertext;
    tampered_ciphertext[15] ^= 0x01; // flip 1 bit

    // 5. Attempt decryption on tampered data
    try {
        aes_gcm_decrypt(key, tampered_ciphertext);
        std::cout << "FAILED: Tampered message was accepted!\n";
    } catch (const std::exception& e) {
        std::cout << "SUCCESS: Tampered message was REJECTED!\n";
        std::cout << "   Reason: " << e.what() << "\n";
    }

    return 0;
}
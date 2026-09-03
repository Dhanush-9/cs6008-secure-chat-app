#include<iostream>
#include "../crypto/dh.hpp"

int main()
{
    DHkeypair dh1 = dh_generate_keypair();
    DHkeypair dh2 = dh_generate_keypair();
    std::cout << "Alice Private Key: " << BignumUniquePtrToHexString(dh1.private_key) << std::endl;
    std::cout << "Bob Private Key: " << BignumUniquePtrToHexString(dh2.private_key) << std::endl;
    std::cout << "Alice Public Key: " << BignumUniquePtrToHexString(dh1.public_key) << std::endl;
    std::cout << "Bob Public Key: " << BignumUniquePtrToHexString(dh2.public_key) << std::endl;

    std::vector<uint8_t> secret1 = dhGetSecret(dh1, dh2.public_key);
    std::vector<uint8_t> secret2 = dhGetSecret(dh2, dh1.public_key);

    std::cout << "Alice's computed secret: ";
    for (uint8_t byte : secret1) {
        std::cout << std::hex << static_cast<int>(byte);
    }
    std::cout << std::endl;

    std::cout << "Bob's computed secret: ";
    for (uint8_t byte : secret2) {
        std::cout << std::hex << static_cast<int>(byte);
    }
    std::cout << std::endl;
}
#include "dh.hpp"

BignumUniquePtr makeBignumUniquePtr(std::string role) {
     BIGNUM* bn = BN_new();
    if (!bn) {
        throw std::runtime_error("Failed to allocate BIGNUM for " + role);
    }
    return BignumUniquePtr(bn);
}

BignumCtxUniquePtr makeBignumCtxUniquePtr(std::string role) {
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to allocate BN_CTX for " + role);
    }
    return BignumCtxUniquePtr(ctx);
}

BignumUniquePtr customHexToBignumUniquePtr(const std::string& hex){
    BIGNUM* bn = nullptr;
    if(!BN_hex2bn(&bn, hex.c_str())) {
        throw std::runtime_error("Failed to convert hex string to BIGNUM");
    }
    return BignumUniquePtr(bn);
}

std::string BnToHexString(const BIGNUM* bn){
    char* hex = BN_bn2hex(bn);
    std::string result(hex);
    OPENSSL_free(hex);
    return result;
}

std::string BignumUniquePtrToHexString(const BignumUniquePtr& bn){
    return BnToHexString(bn.get());
}

const BignumUniquePtr& CalculateDHPrimeOnce() {
    static const BignumUniquePtr prime = customHexToBignumUniquePtr(DH_PrimeHexValue);
    if (!prime) {
        throw std::runtime_error("Failed to load DH Prime");
    }
    return prime;
} //const function only calculates the prime once and returns a reference to it from next calls.

DHkeypair dh_generate_keypair(){
    DHkeypair dh;
    
    const BignumUniquePtr& prime = CalculateDHPrimeOnce();// group prime
    
    BignumUniquePtr base = makeBignumUniquePtr("base");
    BN_set_word(base.get(), DH_base); // group base

    BignumCtxUniquePtr ctx = makeBignumCtxUniquePtr("ctx");

    dh.private_key = makeBignumUniquePtr("private_key");
    dh.public_key = makeBignumUniquePtr("public_key");
    
    if (!BN_rand(dh.private_key.get(), 256, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY))
        throw std::runtime_error("BN_rand failed");

    if (!BN_mod_exp(dh.public_key.get(), base.get(), dh.private_key.get(), prime.get(), ctx.get()))
        throw std::runtime_error("BN_mod_exp failed for public key");

    return dh;
}

std::vector<uint8_t> dhGetSecret(const DHkeypair& dh, const BignumUniquePtr& peer_pub){
    BignumCtxUniquePtr ctx = makeBignumCtxUniquePtr("ctx");

    BignumUniquePtr secret = makeBignumUniquePtr("secret");

    const BignumUniquePtr& prime = CalculateDHPrimeOnce(); // group prime

    if (!BN_mod_exp(secret.get(), peer_pub.get(), dh.private_key.get(), prime.get(), ctx.get()))
        throw std::runtime_error("BN_mod_exp failed for shared secret");

    std::vector<uint8_t> secret_bytes(256);
    BN_bn2binpad(secret.get(), secret_bytes.data(), 256);

    return secret_bytes;
}
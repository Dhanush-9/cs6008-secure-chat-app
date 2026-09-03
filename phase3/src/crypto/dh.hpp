#ifndef DH_HPP
#define DH_HPP
#include<openssl/bn.h>
#include <memory>
#include <vector>
#include <string>
#include <cstdint>
#include <stdexcept> //for std::runtime_error

struct BignumDeleter{
    void operator()(BIGNUM* bn) const {
        if (bn) BN_free(bn);
    }
};

struct BnCtxDeleter{
    void operator()(BN_CTX* ctx) const {
        if (ctx) BN_CTX_free(ctx);
    }
}; //custom deleter for unique_ptr to manage BIGNUM and BN_CTX resources

using BignumUniquePtr = std::unique_ptr<BIGNUM, BignumDeleter>;
using BignumCtxUniquePtr = std::unique_ptr<BN_CTX, BnCtxDeleter>;

inline constexpr const char* DH_PrimeHexValue = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"; //group 14 prime (2048-bit) from RFC 3526

inline constexpr int DH_base = 2;

struct DHkeypair{
    BignumUniquePtr private_key; // our private key (random)
    BignumUniquePtr public_key;  // our public key  = g^priv mod p
};

DHkeypair dh_generate_keypair();
BignumUniquePtr customHexToBignumUniquePtr(const std::string& hex);
BignumUniquePtr makeBignumUniquePtr(std::string role = "");
BignumCtxUniquePtr makeBignumCtxUniquePtr(std::string role = "");
const BignumUniquePtr& CalculateDHPrimeOnce();
std::string BnToHexString(const BIGNUM* bn);
std::string BignumUniquePtrToHexString(const BignumUniquePtr& bn);
std::vector<uint8_t> dhGetSecret(const DHkeypair& dh, const BignumUniquePtr& peer_pub); //returns the vector of bytes instead of BIGNUM because SHA-256(Hash Function) doesn't work directly on BIGNUM, and we need the raw bytes for AES key derivation.


#endif
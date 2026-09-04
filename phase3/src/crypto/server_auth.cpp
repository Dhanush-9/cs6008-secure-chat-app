#include "server_auth.hpp"

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <vector>
#include <string>

bool verify_server_certificate(const std::string& certificate, const std::string& ca_certificate, const std::string& expected_cn){
    
    //convert server certificate string into X509
    BIO* cert_bio = BIO_new_mem_buf(certificate.data(), static_cast<int>(certificate.size()));

    if(cert_bio == nullptr){
        return false;
    }

    X509* server_cert = PEM_read_bio_X509(cert_bio, nullptr, nullptr, nullptr);

    BIO_free(cert_bio);

    if(server_cert == nullptr){
        return false;
    }

    //convert CA certificate string into X509
    BIO* ca_bio = BIO_new_mem_buf(ca_certificate.data(), static_cast<int>(ca_certificate.size()));

    if(ca_bio == nullptr){
        X509_free(server_cert);
        return false;
    }

    X509* ca_cert = PEM_read_bio_X509(ca_bio, nullptr, nullptr, nullptr);

    BIO_free(ca_bio);

    if(ca_cert == nullptr){
        X509_free(server_cert);
        return false;
    }

    //create certificate store
    X509_STORE* store = X509_STORE_new();

    if(store == nullptr){
        X509_free(server_cert);
        X509_free(ca_cert);
        return false;
    }

    //put CA in trust store
    if(X509_STORE_add_cert(store, ca_cert) != 1){
        X509_STORE_free(store);
        X509_free(server_cert);
        X509_free(ca_cert);

        return false;
    }

    //create verification context
    X509_STORE_CTX* context = X509_STORE_CTX_new();

    if (context == nullptr) {
        X509_STORE_free(store);
        X509_free(server_cert);
        X509_free(ca_cert);

        return false;
    }

    if (X509_STORE_CTX_init(context, store, server_cert, nullptr) != 1) {
        X509_STORE_CTX_free(context);
        X509_STORE_free(store);
        X509_free(server_cert);
        X509_free(ca_cert);

        return false;
    }

    int result = X509_verify_cert(context);

    if(result != 1){
        X509_STORE_CTX_free(context);
        X509_STORE_free(store);
        X509_free(server_cert);
        X509_free(ca_cert);

        return false;
    }

    //check against expected cn
    char common_name[256];

    int cn_length = X509_NAME_get_text_by_NID(X509_get_subject_name(server_cert), NID_commonName, common_name, sizeof(common_name));

    if(cn_length < 0){
        X509_STORE_CTX_free(context);
        X509_STORE_free(store);
        X509_free(server_cert);
        X509_free(ca_cert);

        return false;
    }

    if(expected_cn != std::string(common_name, cn_length)){
        X509_STORE_CTX_free(context);
        X509_STORE_free(store);
        X509_free(server_cert);
        X509_free(ca_cert);

        return false;
    }

    //cleanup
    X509_STORE_CTX_free(context);
    X509_STORE_free(store);
    X509_free(server_cert);
    X509_free(ca_cert);

    return true;
}

static std:: string bytes_to_hex(const unsigned char* data, size_t length){
    const char* hex = "0123456789abcdef";

    std::string result;
    result.reserve(length*2);

    for (size_t i = 0; i < length; ++i) {
        result += hex[(data[i] >> 4) & 0x0F];
        result += hex[data[i] & 0x0F];
    }

    return result;
}

std::string generate_challenge()
{
    unsigned char challenge[32];

    if (RAND_bytes(challenge, sizeof(challenge)) != 1) {
        return "";
    }

    return bytes_to_hex(challenge, sizeof(challenge));
}

std::string sign_challenge(const std::string& challenge, const std::string& private_key){

    BIO* key_bio = BIO_new_mem_buf(private_key.data(), static_cast<int>(private_key.size()));

    if (key_bio == nullptr) {
        return "";
    }

    // Read private key
    EVP_PKEY* private_key_obj = PEM_read_bio_PrivateKey( key_bio, nullptr, nullptr, nullptr);

    BIO_free(key_bio);

    if (private_key_obj == nullptr) {
        return "";
    }


    // Create signing context
    EVP_MD_CTX* context = EVP_MD_CTX_new();

    if (context == nullptr) {
        EVP_PKEY_free(private_key_obj);
        return "";
    }


    // SHA-256 signing
    if (EVP_DigestSignInit(context, nullptr, EVP_sha256(), nullptr, private_key_obj) != 1){
        EVP_MD_CTX_free(context);
        EVP_PKEY_free(private_key_obj);
        return "";
    }

    if (EVP_DigestSignUpdate(context, challenge.data(), challenge.size()) != 1){
        EVP_MD_CTX_free(context);
        EVP_PKEY_free(private_key_obj);
        return "";
    }


    // Determine signature size
    size_t signature_size = 0;

    if (EVP_DigestSignFinal(context, nullptr, &signature_size) != 1){
        EVP_MD_CTX_free(context);
        EVP_PKEY_free(private_key_obj);
        return "";
    }

    std::vector<unsigned char> signature(signature_size);

    // Generate signature
    if (EVP_DigestSignFinal(context, signature.data(), &signature_size) != 1){
        EVP_MD_CTX_free(context);
        EVP_PKEY_free(private_key_obj);
        return "";
    }


    // cleanup
    EVP_MD_CTX_free(context);
    EVP_PKEY_free(private_key_obj);

    return bytes_to_hex(signature.data(), signature_size);
}

static int hex_to_value(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }

    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }

    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }

    return -1;
}

bool verify_challenge_response(const std::string& challenge, const std::string& signature, const std::string& certificate){

    BIO* cert_bio = BIO_new_mem_buf(certificate.data(),static_cast<int>(certificate.size()));

    if (cert_bio == nullptr) {
        return false;
    }

    X509* server_cert = PEM_read_bio_X509(cert_bio, nullptr, nullptr, nullptr);

    BIO_free(cert_bio);

    if (server_cert == nullptr) {
        return false;
    }

    // get public key from certificate
    EVP_PKEY* public_key = X509_get_pubkey(server_cert);

    if (public_key == nullptr) {
        X509_free(server_cert);
        return false;
    }


    // convert hex signature back to bytes
    if (signature.size() % 2 != 0) {
        EVP_PKEY_free(public_key);
        X509_free(server_cert);
        return false;
    }

    std::vector<unsigned char> signature_bytes;

    for (size_t i = 0; i < signature.size(); i += 2) {

        int high = hex_to_value(signature[i]);
        int low = hex_to_value(signature[i+1]);

        if(high < 0|| low < 0){
            EVP_PKEY_free(public_key);
            X509_free(server_cert);
            return false;
        }

        unsigned char byte = (high << 4) | low;

        signature_bytes.push_back(byte);
    }


    //verification context
    EVP_MD_CTX* context = EVP_MD_CTX_new();

    if (context == nullptr) {
        EVP_PKEY_free(public_key);
        X509_free(server_cert);
        return false;
    }

    if (EVP_DigestVerifyInit(context, nullptr, EVP_sha256(), nullptr, public_key) != 1){
        EVP_MD_CTX_free(context);
        EVP_PKEY_free(public_key);
        X509_free(server_cert);
        return false;
    }


    // feeding the same challenge for verification
    if (EVP_DigestVerifyUpdate(context, challenge.data(), challenge.size()) != 1){
        EVP_MD_CTX_free(context);
        EVP_PKEY_free(public_key);
        X509_free(server_cert);
        return false;
    }


    // verify signature
    int result = EVP_DigestVerifyFinal(context,signature_bytes.data(),signature_bytes.size());


    // cleanup
    EVP_MD_CTX_free(context);
    EVP_PKEY_free(public_key);
    X509_free(server_cert);


    return result == 1;
}
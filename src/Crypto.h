#ifndef CRYPTO_H
#define CRYPTO_H

#include <string>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

class Crypto {
public:
    Crypto();
    ~Crypto();
    bool loadPrivateKeyFile(const std::string &path);
    bool loadPublicKeyFile(const std::string &path);
    bool loadPrivateKeyStr(const std::string &key);
    bool loadPublicKeyStr(const std::string &key);
    std::string signData(const std::string &data);
    bool verifySignature(const std::string &data, const std::string &signature);
private:
    EVP_PKEY *_privateKey;
    EVP_PKEY *_publicKey;
};

#endif // CRYPTO_H

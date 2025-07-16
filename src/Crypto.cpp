#include "Crypto.h"
#include <iostream>
#include <filesystem>
namespace fs = std::filesystem;

Crypto::Crypto() : _privateKey(nullptr), _publicKey(nullptr) {
    // 仅在OpenSSL 3.0+需要显式初始化
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    // 初始化OpenSSL库
    OpenSSL_add_all_algorithms();
    // 初始化错误处理
    ERR_load_crypto_strings();
#endif
}

Crypto::~Crypto() {
    if (_privateKey) EVP_PKEY_free(_privateKey);
    if (_publicKey) EVP_PKEY_free(_publicKey);
}

bool Crypto::loadPrivateKeyFile(const std::string &path) {
    

    // path 是 UTF-8 字符串
    fs::path filePath = fs::u8path(path);
    // Windows 上转换为宽字符路径
    #ifdef _WIN32
    // 从文件读取 PEM 内容到字符串
    FILE* file = nullptr;
    errno_t err = _wfopen_s(&file, filePath.c_str(), L"r");
    if (err != 0) {
        perror("open PrivateKey file error");
        return false;
    }
    #else
    FILE* file = fopen(filePath.c_str(), "r");
    if(file == nullptr)
    {
        std::cerr << "open PublicKey file error" << std::endl;
        return false;
    }
    #endif

    // 获取文件大小
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // 读取内容到字符串
    char* pem_data = (char*)malloc(size + 1);
    fread(pem_data, 1, size, file);
    pem_data[size] = '\0';  // 确保字符串以 \0 结尾
    fclose(file);
    std::string pem_str(pem_data);
    free(pem_data);
    return loadPrivateKeyStr(pem_str);
}
bool Crypto::loadPrivateKeyStr(const std::string &key) {
    if (_privateKey) {
        EVP_PKEY_free(_privateKey);
        _privateKey = nullptr;
    }
    BIO *bio = BIO_new_mem_buf(key.c_str(), -1);
    if (!bio) {
        std::cerr << "创建BIO失败" << std::endl;
        return false;
    }
    _privateKey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!_privateKey) {
        std::cerr << "读取私钥失败: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        return false;
    }
    return true;
}
bool Crypto::loadPublicKeyFile(const std::string &path) {
    // path 是 UTF-8 字符串
    fs::path filePath = fs::u8path(path);
    // Windows 上转换为宽字符路径
    #ifdef _WIN32
    // 从文件读取 PEM 内容到字符串
    FILE* file = nullptr;
    errno_t err = _wfopen_s(&file, filePath.c_str(), L"r");
    if (err != 0) {
        std::cerr << "open PublicKey file error" << std::endl;
        return false;
    }
    #else
    FILE* file = fopen(filePath.c_str(), "r");
    if(file == nullptr)
    {
        std::cerr << "open PublicKey file error" << std::endl;
        return false;
    }
    #endif
    // 获取文件大小
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // 读取内容到字符串
    char* pem_data = (char*)malloc(size + 1);
    fread(pem_data, 1, size, file);
    pem_data[size] = '\0';  // 确保字符串以 \0 结尾
    fclose(file);
    std::string pem_str(pem_data);
    free(pem_data);
    return loadPublicKeyStr(pem_str);
}
bool Crypto::loadPublicKeyStr(const std::string &key) {
    if (_publicKey) {
        EVP_PKEY_free(_publicKey);
        _publicKey = nullptr;
    }
    BIO *bio = BIO_new_mem_buf(key.c_str(), -1);
    if (!bio) {
        std::cerr << "创建BIO失败" << std::endl;
        return false;
    }
    _publicKey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!_publicKey) {
        std::cerr << "读取公钥失败: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        return false;
    }
    return true;
}
std::string Crypto::signData(const std::string &data) {
    if (!_privateKey) {
        std::cerr << "未加载私钥，无法签名" << std::endl;
        return {};
    }
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        std::cerr << "创建EVP_MD_CTX失败" << std::endl;
        return {};
    }
    // 示例使用SHA256算法，实际可调整
    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, _privateKey) != 1) {
        std::cerr << "初始化签名失败: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        EVP_MD_CTX_free(ctx);
        return {};
    }
    if (EVP_DigestSignUpdate(ctx, data.c_str(), data.size()) != 1) {
        std::cerr << "更新签名数据失败: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        EVP_MD_CTX_free(ctx);
        return {};
    }
    size_t sig_len;
    if (EVP_DigestSignFinal(ctx, nullptr, &sig_len) != 1) {
        std::cerr << "获取签名长度失败: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        EVP_MD_CTX_free(ctx);
        return {};
    }
    std::string signature(sig_len, 0);
    if (EVP_DigestSignFinal(ctx, reinterpret_cast<unsigned char*>(signature.data()), &sig_len) != 1) {
        std::cerr << "生成签名失败: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        EVP_MD_CTX_free(ctx);
        return {};
    }
    EVP_MD_CTX_free(ctx);
    return signature;
}

bool Crypto::verifySignature(const std::string &data, const std::string &signature) {
    if (!_publicKey) {
        std::cerr << "未加载公钥，无法验证" << std::endl;
        return false;
    }
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        std::cerr << "创建EVP_MD_CTX失败" << std::endl;
        return false;
    }
    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, _publicKey) != 1) {
        std::cerr << "初始化验证失败: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        EVP_MD_CTX_free(ctx);
        return false;
    }
    if (EVP_DigestVerifyUpdate(ctx, data.c_str(), data.size()) != 1) {
        std::cerr << "更新验证数据失败: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        EVP_MD_CTX_free(ctx);
        return false;
    }
    int ret = EVP_DigestVerifyFinal(ctx, reinterpret_cast<const unsigned char*>(signature.c_str()), signature.size());
    EVP_MD_CTX_free(ctx);
    if (ret != 1) {
        std::cerr << "验证签名失败: " << (ret == 0 ? "签名不匹配" : ERR_error_string(ERR_get_error(), nullptr)) << std::endl;
        return false;
    }
    return true;
}

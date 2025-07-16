#ifndef BASE64_H
#define BASE64_H

#include <string>
#include <vector>

const static char* base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

// Base64编码
std::string base64_encode(const std::string &bytes) {
    std::string encoded;
    size_t i = 0;
    uint8_t a, b, c;

    // 处理每3个字节
    for (i = 0; i + 2 < bytes.size(); i += 3) {
        a = bytes[i];
        b = bytes[i+1];
        c = bytes[i+2];

        encoded += base64_chars[(a >> 2) & 0x3F];
        encoded += base64_chars[((a << 4) | (b >> 4)) & 0x3F];
        encoded += base64_chars[((b << 2) | (c >> 6)) & 0x3F];
        encoded += base64_chars[c & 0x3F];
    }

    // 处理剩余字节
    if (i < bytes.size()) {
        a = bytes[i];
        encoded += base64_chars[(a >> 2) & 0x3F];

        if (i + 1 < bytes.size()) {
            b = bytes[i+1];
            encoded += base64_chars[((a << 4) | (b >> 4)) & 0x3F];
            encoded += base64_chars[(b << 2) & 0x3F];
        } else {
            encoded += base64_chars[(a << 4) & 0x3F];
        }

        // 添加填充字符
        while (encoded.size() % 4 != 0) {
            encoded += '=';
        }
    }

    return encoded;
}

// Base64解码
std::string base64_decode(const std::string &encoded) {
    std::string decoded;
    std::vector<int> T(256, -1);

    // 初始化查找表
    for (int i = 0; i < 64; i++) {
        T[base64_chars[i]] = i;
    }

    // 处理每4个字符
    int val = 0, val_bits = -8;
    for (uint8_t c : encoded) {
        if (T[c] == -1) break;  // 跳过非Base64字符或填充
        val = (val << 6) + T[c];
        val_bits += 6;
        if (val_bits >= 0) {
            decoded.push_back(char((val >> val_bits) & 0xFF));
            val_bits -= 8;
        }
    }

    return decoded;
}
#endif // BASE64_H

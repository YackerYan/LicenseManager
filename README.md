[中文](#README.md) | [English](#README.en.md)
# License Manager

一个基于C++的许可证管理系统，提供许可证生成、验证和设备指纹识别功能。

## 功能特性

- 使用非对称加密进行许可证签名和验证
- 生成唯一设备指纹识别码
- 支持许可证文件的读写操作
- 提供单例模式管理密钥加载

## 核心模块

- **Crypto**: 提供基于RSA的签名和验证功能
- **DeviceFingerprint**: 收集硬件信息生成设备指纹
- **LicenseManager**: 管理许可证生命周期的核心类

## 使用示例

```cpp
// 初始化许可证管理器
auto manager = LicenseManager::Instance("privateKeyPath", "publicKeyPath");

// 生成许可证
LicenseInfo info;
info.deviceFingerprint = DeviceFingerprint().generateFingerprint();
info.validStart = 1693440000;
info.validEnd = 1725036800;
std::string licenseCode = manager->generateLicenseCode(info);

// 验证许可证
LicenseInfo verifiedInfo;
std::string fingerprint = DeviceFingerprint().generateFingerprint();
bool isValid = manager->verifyLicense(licenseCode, verifiedInfo, fingerprint);
```

## 构建要求

- C++17兼容编译器
- OpenSSL开发库
- CMake 3.14+

## 安装指南

1. 安装依赖: `sudo apt-get install libssl-dev cmake`
2. 创建构建目录: `mkdir build && cd build`
3. 配置项目: `cmake ..`
4. 编译项目: `make`

## 许可证

本项目采用MIT许可证。详见LICENSE文件获取完整许可协议。

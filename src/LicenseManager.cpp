#include "LicenseManager.h"
#include "DeviceFingerprint.h"
#include <chrono>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>
#include <filesystem>
#include "Base64.h"
namespace fs = std::filesystem;

LicenseManager::LicenseManager(const std::string &privateKeyPath,
                               const std::string &publicKeyPath) {
  if (!privateKeyPath.empty())
    _crypto.loadPrivateKeyFile(privateKeyPath);
  if (!publicKeyPath.empty())
    _crypto.loadPublicKeyFile(publicKeyPath);
}

std::string LicenseManager::generateLicenseCode(const LicenseInfo &info) {
  std::string data;
  data << info;
  std::string signature = _crypto.signData(data);
  if(signature.empty())
  {
      return {};
  }
  return base64_encode(data) + "|" + base64_encode(signature);
}

bool LicenseManager::verifyLicense(const std::string &licenseCode,
                                   LicenseInfo &info,
                                   const std::string &deviceFingerprint) {
  std::vector<std::string> parts;
  std::stringstream ss(licenseCode);
  std::string item;
  while (std::getline(ss, item, '|')) {
    parts.push_back(item);
  }
  if (parts.size() != 2)
    return false;
  std::string data = base64_decode(parts[0]);
  std::string signature = base64_decode(parts[1]);
  if (!_crypto.verifySignature(data, signature))
    return false;
  data >> info;
  if (info.deviceFingerprint != deviceFingerprint)
    return false;
  auto now = std::chrono::system_clock::now().time_since_epoch();
  auto now_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
  return now_ms >= info.validStart && now_ms <= info.validEnd;
}

bool LicenseManager::loadPrivateKeyFile(const std::string &path) {
  return _crypto.loadPrivateKeyFile(path);
}

bool LicenseManager::loadPublicKeyFile(const std::string &path) {
  return _crypto.loadPublicKeyFile(path);
}
bool LicenseManager::loadPrivateKeyStr(const std::string &key) {
  return _crypto.loadPrivateKeyStr(key);
}
bool LicenseManager::loadPublicKeyStr(const std::string &key) {
  return _crypto.loadPublicKeyStr(key);
}
LicenseManager *LicenseManager::Instance(const std::string &privateKeyPath,
                                         const std::string &publicKeyPath) {
  static LicenseManager instance(privateKeyPath, publicKeyPath);
  return &instance;
}

bool LicenseManager::saveLicenseToFile(const std::string &licenseData,
                                       const std::string &fileName,
                                       const std::string &fileDir) {
  // 判断Dir是否存在 使用标准库方法
  fs::path dirPath = fs::u8path(fileDir);
  // 判断目录是否存在，不存在则创建
  std::error_code ec;
  if (!fs::exists(dirPath,ec)) {
      if (!fs::create_directories(dirPath, ec)) {
          std::cerr << "无法创建目录: " << ec.message() << std::endl;
          return false;
      }
  }else if (ec) {
      std::cerr << "检查目录存在性失败: " << ec.message() << std::endl;
      return false;
  }
  fs::path filePath = dirPath / fs::u8path(fileName);
  // 打开文件写入
  std::ofstream file(filePath, std::ios::binary);
  if (!file.is_open()) {
    std::cerr << "无法打开文件写入: " << filePath.u8string() << std::endl;
    return false;
  }

  // 写入数据
  file.write(licenseData.data(), licenseData.size());
  if (!file.good()) 
  {
    std::cerr << "写入文件失败: " << filePath.u8string() << std::endl;
    return false;
  }
  return true;
}

bool LicenseManager::loadAndVerifyLicense(const std::string &fileName,
                                          std::string deviceFingerprint,
                                          const std::string &fileDir) {
  // 判断Dir是否存在 使用标准库方法
  fs::path dirPath = fs::u8path(fileDir);
  if (!exists(dirPath)) {
    create_directories(dirPath);
  }
  fs::path filePath = dirPath / fs::u8path(fileName);
  if (!fs::exists(filePath)) {
    std::cerr << "文件不存在: " << filePath << std::endl;
    return false;
  }
  std::ifstream file(filePath,std::ios::binary);
  if (!file.is_open()) {
    std::cerr << "无法打开文件读取: " << fileName << std::endl;
    return false;
  }
  std::string fileData;
  fileData.assign(std::istreambuf_iterator<char>(file),
                  std::istreambuf_iterator<char>());
  file.close();
  // 验证授权码有效性
  if (deviceFingerprint.empty()) {
    deviceFingerprint = DeviceFingerprint::generateFingerprint();
  }
  LicenseInfo info;
  return verifyLicense(fileData, info, deviceFingerprint);
}

// LicenseInfo序列化运算符实现
void operator<<(std::string &data, const LicenseInfo &info) {
  std::stringstream os(std::ios::out | std::ios::binary);
  // 序列化deviceFingerprint
  uint32_t len = static_cast<uint32_t>(info.deviceFingerprint.size());
  os.write(reinterpret_cast<const char *>(&len), sizeof(len));
  os.write(info.deviceFingerprint.data(), len);

  // 序列化validStart
  os.write(reinterpret_cast<const char *>(&info.validStart),
           sizeof(info.validStart));

  // 序列化validEnd
  os.write(reinterpret_cast<const char *>(&info.validEnd),
           sizeof(info.validEnd));

  // 序列化allowedFeatures
  uint32_t featureCount = static_cast<uint32_t>(info.allowedFeatures.size());
  os.write(reinterpret_cast<const char *>(&featureCount), sizeof(featureCount));
  for (const auto &feature : info.allowedFeatures) {
    len = static_cast<uint32_t>(feature.size());
    os.write(reinterpret_cast<const char *>(&len), sizeof(len));
    os.write(feature.data(), len);
  }
  data = os.str();
  return;
}

// LicenseInfo反序列化运算符实现
void operator>>(std::string &data, LicenseInfo &info) {
  std::stringstream is(data,std::ios::in|std::ios::binary);
  // 反序列化deviceFingerprint
  uint32_t len = 0;
  is.read(reinterpret_cast<char *>(&len), sizeof(len));
  info.deviceFingerprint.resize(len);
  is.read(&info.deviceFingerprint[0], len);

  // 反序列化validStart
  is.read(reinterpret_cast<char *>(&info.validStart), sizeof(info.validStart));

  // 反序列化validEnd
  is.read(reinterpret_cast<char *>(&info.validEnd), sizeof(info.validEnd));

  // 反序列化allowedFeatures
  uint32_t featureCount;
  is.read(reinterpret_cast<char *>(&featureCount), sizeof(featureCount));
  info.allowedFeatures.resize(featureCount);
  for (auto &feature : info.allowedFeatures) {
    is.read(reinterpret_cast<char *>(&len), sizeof(len));
    feature.resize(len);
    is.read(&feature[0], len);
  }
  return;
}

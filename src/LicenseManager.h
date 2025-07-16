#ifndef LICENSEMANAGER_H
#define LICENSEMANAGER_H

#include "Crypto.h"
#include <string>
#include <vector>


struct LicenseInfo {
  std::string deviceFingerprint;            ///< 设备指纹
  long long validStart;                     ///< 许可证生效时间戳(秒)
  long long validEnd;                       ///< 许可证过期时间戳(秒)
  std::vector<std::string> allowedFeatures; ///< 允许使用的功能列表

  /**
   * @brief 序列化运算符，将LicenseInfo对象转换为字符串
   * @param data 输出参数，用于存储序列化后的数据
   * @param info 待序列化的LicenseInfo对象
   */
  friend void operator<<(std::string &data, const LicenseInfo &info);
  /**
   * @brief 反序列化运算符，从字符串恢复LicenseInfo对象
   * @param data 包含序列化数据的字符串
   * @param info 输出参数，用于存储反序列化后的对象
   */
  friend void operator>>(std::string &data, LicenseInfo &info);
};

class LicenseManager {
public:
  /**
   * @brief 获取单例实例
   * @param privateKeyPath 私钥文件路径(可选)
   * @param publicKeyPath 公钥文件路径(可选)
   * @return LicenseManager单例指针
   */
  static LicenseManager *Instance(const std::string &privateKeyPath = "",
                                  const std::string &publicKeyPath = "");

  /**
   * @brief 将许可证数据保存到文件
   * @param licenseData 许可证内容字符串
   * @param fileName 文件名
   * @param fileDir 保存目录，默认为"./license"
   * @return 保存成功返回true，失败返回false
   */
  bool saveLicenseToFile(const std::string &licenseData,
                         const std::string &fileName,
                         const std::string &fileDir = "./license");

  /**
   * @brief 从文件加载并验证许可证
   * @param fileName 许可证文件名
   * @param deviceFingerprint 设备指纹(可选)
   * @param fileDir 文件目录，默认为"./license"
   * @return 验证成功返回true，失败返回false
   */
  bool loadAndVerifyLicense(const std::string &fileName,
                            std::string deviceFingerprint = "",
                            const std::string &fileDir = "./license");

  /**
   * @brief 生成许可证代码
   * @param info 许可证信息结构体
   * @return 生成的许可证代码字符串
   */
  std::string generateLicenseCode(const LicenseInfo &info);

  /**
   * @brief 验证许可证的有效性
   * @param licenseCode 待验证的许可证代码字符串
   * @param info 用于存储许可证信息的输出参数
   * @param deviceFingerprint 设备指纹字符串，用于绑定设备验证
   * @return 验证成功返回true，失败返回false
   */
  bool verifyLicense(const std::string &licenseCode, LicenseInfo &info,
                     const std::string &deviceFingerprint);

  /**
   * @brief 从文件加载私钥
   * @param path 私钥文件路径
   * @return 加载成功返回true，失败返回false
   */
  bool loadPrivateKeyFile(const std::string &path);

  /**
   * @brief 从文件加载公钥
   * @param path 公钥文件路径
   * @return 加载成功返回true，失败返回false
   */
  bool loadPublicKeyFile(const std::string &path);

  /**
   * @brief 从字符串加载私钥
   * @param key 私钥字符串
   * @return 加载成功返回true，失败返回false
   */
  bool loadPrivateKeyStr(const std::string &key);
  
  /**
   * @brief 从字符串加载公钥
   * @param key 公钥字符串
   * @return 加载成功返回true，失败返回false
   */
  bool loadPublicKeyStr(const std::string &key);

private:
  // 构造函数改为私有，禁止外部实例化
  LicenseManager(const std::string &privateKeyPath = "",
                 const std::string &publicKeyPath = "");
  // 禁用拷贝构造和赋值操作
  LicenseManager(const LicenseManager &) = delete;
  LicenseManager &operator=(const LicenseManager &) = delete;
  // 禁用移动构造
  LicenseManager(LicenseManager &&) = delete;
  LicenseManager &operator=(LicenseManager &&) = delete;

  Crypto _crypto;
};

#endif // LICENSEMANAGER_H

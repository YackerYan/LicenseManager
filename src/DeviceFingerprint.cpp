#include "DeviceFingerprint.h"
#include <openssl/evp.h>
#include <sstream>
#include <string>
#include <iomanip>
#if defined(_WIN32)
#include <WinSock2.h>
#include <iphlpapi.h>
#include <stdio.h>
#endif

DeviceFingerprint::DeviceFingerprint() {}

std::string DeviceFingerprint::generateFingerprint() {
  std::string cpu = getCpuInfo();
  std::string disk = getDiskSerial();
  std::string mac = getMacAddress();
  std::string data = cpu + "|" + disk + "|" + mac;
  return hashData(data);
}

// 获取CPU信息（通过ACPI固件表）
std::string DeviceFingerprint::getCpuInfo() {
  // 第一步：获取ACPI固件表的大小（第一个参数'ACPI'表示查询ACPI类型的固件表）
  DWORD bufferSize = GetSystemFirmwareTable(*reinterpret_cast<const DWORD*>("ACPI"), 0, nullptr, 0);
  // 检查是否成功获取固件表大小（返回0表示失败）
  if (bufferSize == 0)
    return "";
  // 第二步：分配内存以存储固件表数据
  char *buffer = new char[bufferSize];
  // 调用API获取ACPI固件表内容（第二个参数0表示获取所有子表）
  if (GetSystemFirmwareTable(*reinterpret_cast<const DWORD*>("ACPI"), 0, buffer, bufferSize) == 0) {
    // 获取失败时释放内存并返回空
    delete[] buffer;
    return "";
  }

  // 第三步：将二进制数据转换为十六进制字符串，并截取前64字节
  std::string cpuInfo;
  for (size_t i = 0; i < bufferSize && i < 64; ++i) {
    char hex[3];
    sprintf_s(hex, "%02X", static_cast<unsigned char>(buffer[i]));
    cpuInfo += hex;
  }
  delete[] buffer;
  return cpuInfo;
}

std::string DeviceFingerprint::getDiskSerial() {
  // 打开物理磁盘设备0的句柄（第一个物理磁盘）
  // 参数：设备路径、读权限、共享读写、默认安全属性、打开已存在设备、无额外属性、无模板文件
  HANDLE hDevice = CreateFileW(L"\\.\\PHYSICALDRIVE0", GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                               OPEN_EXISTING, 0, nullptr);
  // 检查句柄是否有效（INVALID_HANDLE_VALUE表示打开失败）
  if (hDevice == INVALID_HANDLE_VALUE)
    return "";
  // 使用IOCTL_STORAGE_QUERY_PROPERTY获取物理磁盘序列号
  STORAGE_PROPERTY_QUERY query = {StorageDeviceProperty, PropertyStandardQuery};
  BYTE buffer[1024] = {0};
  DWORD bytesReturned;
  if (!DeviceIoControl(hDevice, IOCTL_STORAGE_QUERY_PROPERTY, &query,
                       sizeof(query), buffer, sizeof(buffer), &bytesReturned,
                       nullptr)) {
    CloseHandle(hDevice);
    return "";
  }
  // 解析存储设备描述符
  STORAGE_DEVICE_DESCRIPTOR *desc = (STORAGE_DEVICE_DESCRIPTOR *)buffer;
  if (desc->SerialNumberOffset > 0 &&
      desc->SerialNumberOffset < sizeof(buffer)) {
    std::wstring serial =
        std::wstring((WCHAR *)(buffer + desc->SerialNumberOffset));
    // 关闭设备句柄释放资源
    CloseHandle(hDevice);
    // 由于 std::wstring 没有 trimmed 方法，手动实现去除前后空白字符的功能
    std::wstring trimmedSerial = serial;
    // 去除前导空白字符
    while (!trimmedSerial.empty() && iswspace(trimmedSerial.front())) {
      trimmedSerial.erase(trimmedSerial.begin());
    }
    // 去除尾随空白字符
    while (!trimmedSerial.empty() && iswspace(trimmedSerial.back())) {
      trimmedSerial.erase(trimmedSerial.end() - 1);
    }
    // 将宽字符串转换为普通字符串返回
    std::string result;
    result.assign(trimmedSerial.begin(), trimmedSerial.end());
    return result;
  }
  // 关闭设备句柄避免资源泄漏
  CloseHandle(hDevice);
  return "";
}

std::string DeviceFingerprint::getMacAddress() {
  // 初始化适配器信息指针和缓冲区长度变量
  IP_ADAPTER_INFO *pAdapterInfo = nullptr;
  ULONG ulOutBufLen = 0;
  // 首次调用获取所需缓冲区大小（ERROR_BUFFER_OVERFLOW表示需要更大的缓冲区）
  if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
    // 分配足够大小的缓冲区存储适配器信息
    pAdapterInfo = (IP_ADAPTER_INFO *)new BYTE[ulOutBufLen];
    // 再次调用获取适配器信息（检查是否成功）
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) != ERROR_SUCCESS) {
      delete[] pAdapterInfo;
      return "";
    }
  } else {
    return "";
  }
  // 遍历适配器信息链表
  IP_ADAPTER_INFO *pAdapter = pAdapterInfo;
  std::string mac;
  // 循环检查每个网络适配器
  while (pAdapter) {
    // 仅处理以太网类型的适配器（排除无线、虚拟等其他类型）
    if (pAdapter->Type == MIB_IF_TYPE_ETHERNET) {
      std::stringstream ss;
      ss << std::hex << std::uppercase << std::setfill('0');
      for (int i = 0; i < 6; ++i) {
        if (i > 0) {
          ss << "-";
        }
        ss << std::setw(2) << static_cast<int>(pAdapter->Address[i] & 0xFF);
      }
      std::string mac = ss.str();
      break;
    }
    pAdapter = pAdapter->Next;
  }
  // 释放适配器信息内存避免泄漏
  delete pAdapterInfo;
  return mac;
}

// 对输入数据进行SHA-256哈希计算
std::string DeviceFingerprint::hashData(const std::string &data) {
  // 初始化EVP上下文
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) {
    return "";
  }

  // 初始化SHA-256哈希
  if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
    EVP_MD_CTX_free(ctx);
    return "";
  }

  // 更新哈希数据
  if (EVP_DigestUpdate(ctx, data.c_str(), data.size()) != 1) {
    EVP_MD_CTX_free(ctx);
    return "";
  }

  // 完成哈希计算
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int len;
  if (EVP_DigestFinal_ex(ctx, hash, &len) != 1) {
    EVP_MD_CTX_free(ctx);
    return "";
  }

  // 释放上下文
  EVP_MD_CTX_free(ctx);

  // 转换为十六进制字符串
  std::stringstream ss;
  for (unsigned int i = 0; i < len; i++) {
    ss << std::hex << std::setw(2) << std::setfill('0')
       << static_cast<int>(hash[i]);
  }
  return ss.str();
}

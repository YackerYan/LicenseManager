#ifndef DEVICEFINGERPRINT_H
#define DEVICEFINGERPRINT_H

#include <string>

class DeviceFingerprint {
public:
    DeviceFingerprint();
    static std::string generateFingerprint();

private:
    static std::string getCpuInfo();
    static std::string getDiskSerial();
    static std::string getMacAddress();
    static std::string hashData(const std::string &data);
};

#endif // DEVICEFINGERPRINT_H

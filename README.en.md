[中文](README.md) | [English](README.en.md)
# License Manager

A C++-based license management system that provides functions for license generation, validation, and device fingerprint identification.

## Features

- Uses asymmetric encryption for license signing and verification
- Generates unique device fingerprint identifiers
- Supports reading and writing license files
- Provides singleton pattern for key loading management

## Core Modules

- **Crypto**: Provides RSA-based signing and verification capabilities
- **DeviceFingerprint**: Collects hardware information to generate device fingerprints
- **LicenseManager**: Core class managing the license lifecycle

## Usage Example

```cpp
// Initialize the license manager
auto manager = LicenseManager::Instance("privateKeyPath", "publicKeyPath");

// Generate a license
LicenseInfo info;
info.deviceFingerprint = DeviceFingerprint().generateFingerprint();
info.validStart = 1693440000;
info.validEnd = 1725036800;
std::string licenseCode = manager->generateLicenseCode(info);

// Verify a license
LicenseInfo verifiedInfo;
std::string fingerprint = DeviceFingerprint().generateFingerprint();
bool isValid = manager->verifyLicense(licenseCode, verifiedInfo, fingerprint);
```

## Build Requirements

- C++17 compatible compiler
- OpenSSL development library
- CMake 3.14+

## Installation Guide

1. Install dependencies: `sudo apt-get install libssl-dev cmake`
2. Create build directory: `mkdir build && cd build`
3. Configure project: `cmake ..`
4. Build project: `make`

## License

This project uses the MIT License. See the LICENSE file for the complete license agreement.

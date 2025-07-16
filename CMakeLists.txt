cmake_minimum_required(VERSION 3.19)
project(LicenseManager LANGUAGES CXX)

# 设置C++标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 设置编码选项
if(MSVC)
    add_compile_options(/utf-8)
    add_compile_options(/Zc:__cplusplus)
elseif(MINGW)
    add_compile_options(-finput-charset=UTF-8)
endif()


# 查找OpenSSL库
# 使用本地静态库
set(OpenSSL_USE_STATIC_LIBS ON)
find_package(OpenSSL REQUIRED HINTS $ENV{THIRD_PARTY_DIR})


add_subdirectory(src)
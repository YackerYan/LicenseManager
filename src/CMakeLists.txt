# 自动收集当前目录下的所有 .cpp 和 .h 文件
file(GLOB_RECURSE LICENSEMANAGER_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/*.h
)

# 选项：是否编译为DLL
option(BUILD_DLL "Build as DLL" ON)

# 检测平台和架构
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(ARCHITECTURE "x64")
else()
    set(ARCHITECTURE "x86")
endif()
set(PLATFORM_DIR ${CMAKE_SYSTEM_NAME}/${ARCHITECTURE})

# 创建动态库
if(BUILD_DLL)
    add_library(LicenseManager SHARED
        ${LICENSEMANAGER_SOURCES}
    )
    set_target_properties(LicenseManager PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        WINDOWS_EXPORT_ALL_SYMBOLS ON
    )

    target_link_libraries(LicenseManager
        PUBLIC
        OpenSSL::Crypto
        OpenSSL::SSL
        iphlpapi
    )
else()
    # 创建静态库
    add_library(LicenseManager STATIC
        ${LICENSEMANAGER_SOURCES}
    )
    set_target_properties(LicenseManager PROPERTIES
        ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    )

    target_link_libraries(LicenseManager
        PUBLIC
        OpenSSL::Crypto
        OpenSSL::SSL
        iphlpapi
    )
endif()


# 安装配置
if(DEFINED ENV{THIRD_PARTY_DIR})
    set(CMAKE_INSTALL_PREFIX "$ENV{THIRD_PARTY_DIR}/LicenseManager")
else()
    set(CMAKE_INSTALL_PREFIX "${CMAKE_BINARY_DIR}/install")
endif()

# 安装头文件
install(FILES
    LicenseManager.h
    DeviceFingerprint.h
    DESTINATION include
)



# 安装动态库并导出目标
if(BUILD_DLL)
    install(TARGETS LicenseManager
    EXPORT LicenseManagerTargets
    RUNTIME DESTINATION bin/${PLATFORM_DIR}/$<CONFIG>
    LIBRARY DESTINATION lib/${PLATFORM_DIR}/$<CONFIG>
)
else()
    # 安装静态库并导出目标
install(TARGETS LicenseManager
    EXPORT LicenseManagerTargets
    ARCHIVE DESTINATION lib/${PLATFORM_DIR}/$<CONFIG>
)
endif()

# 生成配置文件
include(CMakePackageConfigHelpers)
configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/../cmake/LicenseManagerConfig.cmake.in"
    "${CMAKE_BINARY_DIR}/LicenseManagerConfig.cmake"
    INSTALL_DESTINATION cmake
)

# 导出目标配置
install(EXPORT LicenseManagerTargets
    FILE LicenseManagerTargets.cmake
    DESTINATION cmake
)

# 安装配置文件
install(FILES
    "${CMAKE_BINARY_DIR}/LicenseManagerConfig.cmake"
    DESTINATION cmake
)

# 安装CMake配置文件
install(DIRECTORY
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake
    DESTINATION .
    FILES_MATCHING PATTERN *.cmake
)
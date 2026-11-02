# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
# An outside consumer of the installed package: the existing C++ smoke test, built
# against find_package(iya_saml) rather than this source tree. The Docker test stage
# builds and runs it against both the static and the shared install.
cmake_minimum_required(VERSION 3.16)
project(iya_saml_package_test LANGUAGES C CXX)
find_package(iya_saml ${iya_saml_EXPECTED_VERSION} EXACT REQUIRED)
add_executable(consumer ${CMAKE_CURRENT_SOURCE_DIR}/../../tests/cpp_api_test.cpp)
target_link_libraries(consumer PRIVATE iya::saml)

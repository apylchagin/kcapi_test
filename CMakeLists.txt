cmake_minimum_required(VERSION 3.18 FATAL_ERROR)
project(kcapi_test LANGUAGES C CXX)


include(FindOpenSSL)

add_subdirectory(kcapi)
add_subdirectory(gtest)


add_executable(${PROJECT_NAME} code/main.cc)

target_link_libraries(${PROJECT_NAME} PRIVATE gtest kcapi ${OPENSSL_CRYPTO_LIBRARY})

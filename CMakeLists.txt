cmake_minimum_required(VERSION 3.18 FATAL_ERROR)
project(kcapi_test LANGUAGES C CXX)

include(FindOpenSSL)

option(KCAPI_USE_PREBUILD "Use the pre-build library via autotools" ON)
option(KCAPI_USE_SYSTEM "Use the system-installed library" OFF)


if (KCAPI_USE_SYSTEM)
    pkg_check_modules(KCAPI QUIET libkcapi kcapi kcapi1)
    if (NOT KCAPI_FOUND)
        # Try to find the library
        find_library(KCAPI_LIBRARIES NAMES libkcapi kcapi kcapi1)
        if (KCAPI_LIBRARIES)
            set(KCAPI_FOUND 1)
            set(KCAPI_INCLUDE_DIRS "/usr/include" "/usr/local/include")
        else ()
            set(KCAPI_FOUND 0)
        endif ()
    endif ()
elseif (KCAPI_USE_PREBUILD)
else ()
    add_subdirectory(kcapi)
endif ()

add_subdirectory(gtest)


add_executable(${PROJECT_NAME} code/main.cc)

if (KCAPI_USE_SYSTEM)
    target_link_libraries(${PROJECT_NAME} PRIVATE ${KCAPI_LIBRARIES})
    target_include_directories(${PROJECT_NAME} PRIVATE ${KCAPI_INCLUDE_DIRS})
elseif (KCAPI_USE_PREBUILD)
    target_include_directories(${PROJECT_NAME} BEFORE PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/kcapi/code/lib)
    target_link_directories(${PROJECT_NAME} PRIVATE BEFORE ${CMAKE_CURRENT_SOURCE_DIR}/kcapi/code/.libs)
endif ()

target_link_libraries(${PROJECT_NAME} PRIVATE gtest kcapi ${OPENSSL_CRYPTO_LIBRARY})

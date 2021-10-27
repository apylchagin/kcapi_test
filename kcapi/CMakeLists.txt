cmake_minimum_required(VERSION 3.10 FATAL_ERROR)
project(kcapi LANGUAGES C)

option(DISABLE_LIB_SYM  "" OFF)
option(DISABLE_LIB_MD   "" OFF)
option(DISABLE_LIB_KDF  "" OFF)
option(DISABLE_LIB_AEAD "" OFF)
option(DISABLE_LIB_RNG  "" OFF)
option(ENABLE_LIB_ASYM  "" OFF)
option(ENABLE_LIB_KPP   "" OFF)

# Read the version from the configure file
function(kcapi_read_version _file)
    file(STRINGS ${_file} KCAPI_VERSION
         REGEX "^m4_define\\(\\[__KCAPI_[A-Z]+\\], \\[[0-9]+\\]\\)")
    foreach(_string ${KCAPI_VERSION})
        string(REGEX MATCH "^m4_define\\(\\[__KCAPI_([A-Z]+)\\], \\[([0-9]+)\\]\\)"
               _val ${_string})
        set(KCAPI_${CMAKE_MATCH_1} ${CMAKE_MATCH_2} PARENT_SCOPE)
    endforeach ()
endfunction()

kcapi_read_version(${CMAKE_CURRENT_SOURCE_DIR}/code/configure.ac)

list(APPEND SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/code/lib/kcapi-kernel-if.c
    ${CMAKE_CURRENT_SOURCE_DIR}/code/lib/kcapi-utils.c)

list(APPEND HEADERS
    ${CMAKE_CURRENT_SOURCE_DIR}/code/lib/cryptouser.h
    ${CMAKE_CURRENT_SOURCE_DIR}/code/lib/internal.h
    ${CMAKE_CURRENT_SOURCE_DIR}/code/lib/kcapi.h)

if (NOT DISABLE_LIB_SYM)
    list(APPEND SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/code/lib/kcapi-sym.c)
endif ()

if (NOT DISABLE_LIB_MD)
    list(APPEND SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/code/lib/kcapi-md.c)
    if (NOT DISABLE_LIB_KDF)
        list(APPEND SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/code/lib/kcapi-kdf.c)
    endif ()
endif ()

if (NOT DISABLE_LIB_AEAD)
    list(APPEND SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/code/lib/kcapi-aead.c)
endif ()

if (NOT DISABLE_LIB_RNG)
    list(APPEND SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/code/lib/kcapi-rng.c)
endif ()

if (ENABLE_LIB_ASYM)
    list(APPEND SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/code/lib/kcapi-asym.c)
endif ()

if (ENABLE_LIB_KPP)
    list(APPEND SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/code/lib/kcapi-kpp.c)
endif ()

add_library(${PROJECT_NAME} SHARED ${SOURCES} ${HEADERS})

set_target_properties(${PROJECT_NAME} PROPERTIES UNITY_BUILD OFF
                                                 FOLDER "external"
                                                 EXCLUDE_FROM_ALL ON)
set(KCAPI_VERSION "${KCAPI_MAJVERSION}.${KCAPI_MINVERSION}.${KCAPI_PATCHLEVEL}")
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/code/lib)
target_compile_definitions(${PROJECT_NAME} PRIVATE -DKCAPI_MAJVERSION=${KCAPI_MAJVERSION}
                                                   -DKCAPI_MINVERSION=${KCAPI_MINVERSION}
                                                   -DKCAPI_PATCHLEVEL=${KCAPI_PATCHLEVEL}
                                                   -DCHECK_PREFIX=.
                                                   -DPACKAGE_VERSION="${KCAPI_VERSION}"
                                                   -DVERSION="${KCAPI_VERSION}")
if(CMAKE_SYSTEM_NAME STREQUAL "Android")
    target_link_libraries(${PROJECT_NAME} PRIVATE log)
endif ()

set(local_link_flags -Wl,--version-script,${CMAKE_CURRENT_SOURCE_DIR}/code/lib/version.lds)
if (CMAKE_VERSION GREATER 3.13)
    target_link_options(${PROJECT_NAME} PRIVATE ${local_link_flags})
else ()
    set_property(TARGET ${PROJECT_NAME} APPEND PROPERTY LINK_FLAGS ${local_link_flags})
endif ()
set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${KCAPI_VERSION}
                                                 SOVERSION ${KCAPI_VERSION})

install(TARGETS ${PROJECT_NAME} OPTIONAL
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib/static
    PUBLIC_HEADER DESTINATION include)

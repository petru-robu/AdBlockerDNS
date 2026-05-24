cmake_minimum_required(VERSION 3.20)

project(adblocker
    VERSION 0.1.0
    DESCRIPTION "AdBlocking project"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Threads REQUIRED)

add_library(dns_resolver_core
    src/dns_name.cpp
    src/dns_message.cpp
    src/udp_server.cpp
    src/rec_resolver.cpp
)

target_include_directories(dns_resolver_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/inc
)

target_link_libraries(dns_resolver_core
    PUBLIC
        Threads::Threads
)

target_compile_features(dns_resolver_core
    PUBLIC
        cxx_std_20
)

add_executable(dns-resolver
    app/main.cpp
)

target_link_libraries(dns-resolver
    PRIVATE
        dns_resolver_core
)
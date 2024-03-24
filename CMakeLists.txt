cmake_minimum_required(VERSION 2.6)
project(http-proxy)


set(CMAKE_INCLUDE_CURRENT_DIR ON)

option(WITH_ASAN "with address sanitierze" ON)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
link_directories(${OPENSSL_LIBRARY_DIR})

find_package(nlohmann_json CONFIG REQUIRED)

find_package(spdlog CONFIG REQUIRED)
INCLUDE_DIRECTORIES(${spdlog_include_dirs})


# set(ASIO_DIR "D:\\Github\\asio-1.10.6\\include")
include_directories(${ASIO_DIR})
add_definitions(-DASIO_STANDALONE)

include_directories(${CMAKE_SOURCE_DIR}/include)




set(CMAKE_CXX_STANDARD 17)

if(MSVC)
add_definitions(-DBOOST_ASIO_HAS_MOVE)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /std:c++latest")
add_definitions(-DASIO_MSVC)
endif(MSVC)

if(WITH_ASAN)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wno-unused-parameter -fsanitize=address -fno-omit-frame-pointer")
else()
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wno-unused-parameter")
endif(WITH_ASAN)


add_library(kcp ${CMAKE_SOURCE_DIR}/kcp/ikcp.c)

file(GLOB_RECURSE PROXY_BASIC_SRCS ${CMAKE_SOURCE_DIR}/src/proxy_basic/*.cpp)
file(GLOB_RECURSE CLIENT_BASIC_SRCS ${CMAKE_SOURCE_DIR}/src/client_basic/*.cpp)
file(GLOB_RECURSE SERVER_BASIC_SRCS ${CMAKE_SOURCE_DIR}/src/server_basic/*.cpp)
file(GLOB_RECURSE CLIENT_PERSIST_SRCS ${CMAKE_SOURCE_DIR}/src/client_persist/*.cpp)
file(GLOB_RECURSE SERVER_PERSIST_SRCS ${CMAKE_SOURCE_DIR}/src/server_persist/*.cpp)
file(GLOB_RECURSE RELAY_SRCS ${CMAKE_SOURCE_DIR}/src/relay/*.cpp)

add_library(proxy_basic_lib ${PROXY_BASIC_SRCS})
target_link_libraries(proxy_basic_lib nlohmann_json::nlohmann_json 	spdlog::spdlog ${OPENSSL_LIBRARIES} kcp)

add_library(client_basic_lib ${CLIENT_BASIC_SRCS})
target_link_libraries(client_basic_lib proxy_basic_lib)

add_library(server_basic_lib ${SERVER_BASIC_SRCS})
target_link_libraries(server_basic_lib proxy_basic_lib)


add_library(client_persist_lib ${CLIENT_PERSIST_SRCS})

target_link_libraries(client_persist_lib client_basic_lib)

add_library(server_persist_lib ${SERVER_PERSIST_SRCS})
target_link_libraries(server_persist_lib server_basic_lib)

add_library(relay_lib ${RELAY_SRCS})
target_link_libraries(relay_lib proxy_basic_lib)


add_executable(client_basic test/http_proxy_client_basic_main.cpp )
target_link_libraries(client_basic client_basic_lib)

add_executable(server_basic test/http_proxy_server_basic_main.cpp )
target_link_libraries(server_basic server_basic_lib)

add_executable(client_persist test/http_proxy_client_persist_main.cpp )
target_link_libraries(client_persist client_persist_lib)

add_executable(server_persist test/http_proxy_server_persist_main.cpp )
target_link_libraries(server_persist server_persist_lib)

add_executable(relay test/http_proxy_relay_main.cpp )
target_link_libraries(relay relay_lib)

add_executable(parser_test  test/http_parser_test.cpp)
target_link_libraries(parser_test proxy_basic_lib)


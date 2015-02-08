cmake_minimum_required(VERSION 2.6)
project(azure-http-proxy)

set(Boost_USE_MULTITHREAD ON)

find_package(Boost REQUIRED COMPONENTS system)
find_package(OpenSSL REQUIRED)

include_directories(${Boost_INCLUDE_DIR})
link_directories(${Boost_LIBRARY_DIR})

include_directories(${OPENSSL_INCLUDE_DIR})
link_directories(${OPENSSL_LIBRARY_DIR})

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -O3")

add_executable(ahpc src/http_proxy_client_main.cpp src/http_proxy_client.cpp src/http_proxy_client_stat.cpp src/http_proxy_client_config.cpp src/http_proxy_client_connection.cpp src/jsonxx/jsonxx.cc)
target_link_libraries(ahpc ${Boost_SYSTEM_LIBRARY} ${OPENSSL_CRYPTO_LIBRARIES} pthread)

add_executable(ahps src/http_proxy_server_main.cpp src/http_proxy_server.cpp src/http_proxy_server_config.cpp src/http_proxy_server_connection.cpp src/http_header_parser.cpp src/jsonxx/jsonxx.cc)
target_link_libraries(ahps ${Boost_SYSTEM_LIBRARY} ${OPENSSL_CRYPTO_LIBRARIES} pthread)
cmake_minimum_required(VERSION 2.6)
project(azure-http-proxy)



find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
link_directories(${OPENSSL_LIBRARY_DIR})

find_package(nlohmann_json CONFIG REQUIRED)

OPTION(ASIO_STANDALONE "use asio without boost" ON)

find_package(spdlog CONFIG REQUIRED)
INCLUDE_DIRECTORIES(${spdlog_include_dirs})

if(ASIO_STANDALONE)
set(ASIO_DIR "C:\\Users\\hhln4510\\Documents\\Github\\asio\\asio\\include")
# set(ASIO_DIR "D:\\Github\\asio-1.10.6\\include")
include_directories(${ASIO_DIR})
add_definitions(-DASIO_STANDALONE)
add_definitions(-DASIO_MSVC)
else()
find_package(Boost REQUIRED COMPONENTS system regex asio)
include_directories(${Boost_INCLUDE_DIR})
link_directories(${Boost_LIBRARY_DIR})
endif()

set(CMAKE_CXX_STANDARD 17)

if(MSVC)
add_definitions(-DBOOST_ASIO_HAS_MOVE)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /std:c++latest")
endif(MSVC)

add_executable(parser_test src/http_header_parser.cpp src/http_parser_test.cpp)
target_link_libraries(parser_test ${OPENSSL_LIBRARIES})

add_executable(ahpc src/http_proxy_client_main.cpp src/http_proxy_client.cpp src/http_proxy_client_stat.cpp src/http_proxy_client_config.cpp src/http_proxy_client_connection.cpp src/http_header_parser.cpp)

if(ASIO_STANDALONE)
target_link_libraries(ahpc ${OPENSSL_LIBRARIES})
else()
target_link_libraries(ahpc ${Boost_SYSTEM_LIBRARY} ${OPENSSL_LIBRARIES})
endif()

add_executable(ahps src/http_proxy_server_main.cpp src/http_proxy_server.cpp src/http_proxy_server_config.cpp src/http_proxy_server_connection.cpp src/http_header_parser.cpp src/base64.cpp src/authentication.cpp )

if(ASIO_STANDALONE)
target_link_libraries(ahps  ${OPENSSL_LIBRARIES})
else()
target_link_libraries(ahps  ${Boost_SYSTEM_LIBRARY} ${Boost_REGEX_LIBRARY} ${OPENSSL_LIBRARIES})
endif()

target_link_libraries(ahps PRIVATE nlohmann_json::nlohmann_json)
target_link_libraries(ahpc PRIVATE nlohmann_json::nlohmann_json)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  target_link_libraries(ahpc atomic)
endif()

if(UNIX)
  target_link_libraries(ahpc pthread)
  target_link_libraries(ahps pthread)
endif()

if(WIN32)
  if(MINGW)
    target_link_libraries(ahpc ws2_32 wsock32)
    target_link_libraries(ahps ws2_32 wsock32)
  endif()
endif()
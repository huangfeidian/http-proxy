cmake_minimum_required(VERSION 2.6)
project(azure-http-proxy)



find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
link_directories(${OPENSSL_LIBRARY_DIR})

find_package(nlohmann_json CONFIG REQUIRED)

find_package(spdlog CONFIG REQUIRED)
INCLUDE_DIRECTORIES(${spdlog_include_dirs})


# set(ASIO_DIR "D:\\Github\\asio-1.10.6\\include")
# include_directories(${ASIO_DIR})
add_definitions(-DASIO_STANDALONE)
add_definitions(-DASIO_MSVC)


set(CMAKE_CXX_STANDARD 17)

if(MSVC)
add_definitions(-DBOOST_ASIO_HAS_MOVE)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /std:c++latest")
endif(MSVC)

add_executable(parser_test src/http_header_parser.cpp src/http_parser_test.cpp)
target_link_libraries(parser_test ${OPENSSL_LIBRARIES})

add_executable(ahpc_basic 
src/http_proxy_client_basic_main.cpp 
src/http_proxy_client_basic.cpp 
src/http_proxy_client_stat.cpp 
src/http_proxy_client_config.cpp 
src/http_proxy_client_connection.cpp 
src/http_proxy_connection.cpp
src/http_header_parser.cpp)

add_executable(ahpc_persist 
src/http_proxy_client_persist_main.cpp 
src/http_proxy_client_persist.cpp 
src/http_proxy_client_stat.cpp 
src/http_proxy_client_config.cpp 
src/http_proxy_client_connection.cpp 
src/http_proxy_connection.cpp
src/http_proxy_session_manager.cpp
src/http_proxy_client_session_manager.cpp
src/http_proxy_client_session.cpp
src/http_header_parser.cpp)


add_executable(ahps_basic
src/http_proxy_server_basic_main.cpp 
src/http_proxy_server_basic.cpp 
src/http_proxy_server_config.cpp 
src/http_proxy_connection.cpp
src/http_proxy_server_connection.cpp 
src/http_header_parser.cpp 
src/base64.cpp 
src/authentication.cpp )

add_executable(ahps_persist
src/http_proxy_server_persist_main.cpp 
src/http_proxy_server_persist.cpp 
src/http_proxy_server_config.cpp 
src/http_proxy_connection.cpp
src/http_proxy_server_connection.cpp
src/http_proxy_server_session.cpp 
src/http_proxy_server_session_manager.cpp
src/http_proxy_session_manager.cpp
src/http_header_parser.cpp 
src/base64.cpp 
src/authentication.cpp )

target_link_libraries(ahps_basic  ${OPENSSL_LIBRARIES})
target_link_libraries(ahpc_basic  ${OPENSSL_LIBRARIES})
target_link_libraries(ahps_persist  ${OPENSSL_LIBRARIES})
target_link_libraries(ahpc_persist  ${OPENSSL_LIBRARIES})

target_link_libraries(ahps_basic PRIVATE nlohmann_json::nlohmann_json)
target_link_libraries(ahpc_basic PRIVATE nlohmann_json::nlohmann_json)
target_link_libraries(ahps_persist PRIVATE nlohmann_json::nlohmann_json)
target_link_libraries(ahpc_persist PRIVATE nlohmann_json::nlohmann_json)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  target_link_libraries(ahpc_basic atomic)
  target_link_libraries(ahps_basic atomic)
  target_link_libraries(ahpc_persist atomic)
  target_link_libraries(ahps_persist atomic)
endif()

if(UNIX)
  target_link_libraries(ahpc_basic pthread)
  target_link_libraries(ahps_basic pthread)
  target_link_libraries(ahpc_persist pthread)
  target_link_libraries(ahps_persist pthread)
endif()

if(WIN32)
  if(MINGW)
    target_link_libraries(ahpc_basic ws2_32 wsock32)
    target_link_libraries(ahps_basic ws2_32 wsock32)
    target_link_libraries(ahpc_persist ws2_32 wsock32)
    target_link_libraries(ahps_persist ws2_32 wsock32)
  endif()
endif()
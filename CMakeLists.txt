cmake_minimum_required(VERSION 2.6)
project(azure-http-proxy)

include_directories(./src/json/src)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
link_directories(${OPENSSL_LIBRARY_DIR})


OPTION(ASIO_STANDALONE "use asio without boost" ON)

if(ASIO_STANDALONE)
set(ASIO_DIR "D:\\Github\\asio\\asio\\include")
include_directories(${ASIO_DIR})
add_definitions(-DASIO_STANDALONE)
add_definitions(-DASIO_HAS_STD_ARRAY )
add_definitions(-DASIO_HAS_MOVE )
add_definitions(-DASIO_HAS_STD_SHARED_PTR )
add_definitions(-DASIO_HAS_WEAK_PTR )
add_definitions(-DASIO_HAS_STD_ADDRESSOF )
add_definitions(-DASIO_HAS_STD_SYSTEM_ERROR )
add_definitions(-DASIO_HAS_STD_ATOMIC )
add_definitions(-DASIO_HAS_CSTDINT )
add_definitions(-DASIO_HAS_NULLPTR )
add_definitions(-DASIO_HAS_STD_TYPE_TRAITS )
else()
find_package(Boost REQUIRED COMPONENTS system regex)
include_directories(${Boost_INCLUDE_DIR})
link_directories(${Boost_LIBRARY_DIR})
endif()

if("${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang")
  add_definitions(-DBOOST_ASIO_HAS_MOVE)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++1y")
elseif("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++1y")
endif()



add_executable(ahpc src/http_proxy_client_main.cpp src/http_proxy_client.cpp src/http_proxy_client_stat.cpp src/http_proxy_client_config.cpp src/http_proxy_client_connection.cpp )

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
/*
 *    http_proxy_client_connection.hpp:
 *
 *    Copyright (C) 2019-2021 spiritsaway.info All Rights Reserved.
 *
 */

#pragma once

#include <array>
#include <chrono>
#include <memory>
#include <vector>

#include "http_proxy_client_connection.hpp"
namespace azure_proxy
{
    class http_proxy_client_session_manager;
    class http_proxy_client_session: public http_proxy_client_connection
    {
    public:
        http_proxy_client_session(asio::ip::tcp::socket&& ua_socket, std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count, http_proxy_client_session_manager& in_session_manager);
        static std::shared_ptr<http_proxy_client_session> create(asio::ip::tcp::socket&& ua_socket, asio::ip::tcp::socket&& _server_socket,std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count, http_proxy_client_session_manager& in_session_manager);
    private:
        http_proxy_client_session_manager& _session_manager;

    }
    
}

#pragma once
#include "http_proxy_session_manager.hpp"


namespace azure_proxy
{
    class http_proxy_client_session_manager: public http_proxy_session_manager
    {
    public:

        http_proxy_client_session_manager(asio::io_service& _in_io_service, std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count);
        static std::shared_ptr<http_proxy_client_session_manager> create(asio::io_service& _in_io_service, std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count);
    
    };
}
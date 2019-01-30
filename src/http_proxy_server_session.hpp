#pragma once

#include <array>
#include <chrono>
#include <memory>
#include <vector>

#include "http_proxy_server_connection.hpp"
namespace azure_proxy
{
    class http_proxy_server_session_manager;
    class http_proxy_server_session: public http_proxy_server_connection
    {
    public:
        http_proxy_server_session(asio::ip::tcp::socket&& ua_socket, asio::ip::tcp::socket&& _server_socket, std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count, http_proxy_server_session_manager& in_session_manager);
        static std::shared_ptr<http_proxy_server_session> create(asio::ip::tcp::socket&& ua_socket, asio::ip::tcp::socket&& _server_socket,std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count, http_proxy_server_session_manager& in_session_manager);
		~http_proxy_server_session();
		void async_read_data_from_client(bool set_timer, std::size_t at_least_size, std::size_t at_most_size);
		void async_send_data_to_client(std::size_t offset, std::size_t size);
    private:
        http_proxy_server_session_manager& _session_manager;

	};
    
}

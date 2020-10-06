#pragma once

#include <array>
#include <chrono>
#include <memory>
#include <vector>

#include "http_proxy_server_connection.hpp"
namespace http_proxy
{
    class http_proxy_server_session_manager;
    class http_proxy_server_session: public http_proxy_server_connection
    {
    public:
        http_proxy_server_session(asio::io_context& in_io, asio::ip::tcp::socket&& ua_socket, asio::ip::tcp::socket&& _server_socket, std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count, std::shared_ptr<http_proxy_server_session_manager> in_session_manager, std::uint32_t in_client_session_count);
        static std::shared_ptr<http_proxy_server_session> create(asio::io_context& in_io, asio::ip::tcp::socket&& ua_socket, asio::ip::tcp::socket&& _server_socket,std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count, std::shared_ptr<http_proxy_server_session_manager> in_session_manager, std::uint32_t in_client_session_count);
		void start() override;
		void async_read_data_from_client(bool set_timer = true, std::size_t at_least_size = 1, std::size_t at_most_size = BUFFER_LENGTH)override;
		void async_send_data_to_client(const unsigned char* write_buffer, std::size_t offset, std::size_t size) override;
		void on_client_data_arrived(std::size_t bytes_transferred) override;
		void on_client_data_send(std::size_t bytes_transferred) override;
    private:
		std::weak_ptr<http_proxy_server_session_manager> _session_manager;
	protected:
		void close_connection();
		const std::uint32_t client_session_count;
	};
    
}

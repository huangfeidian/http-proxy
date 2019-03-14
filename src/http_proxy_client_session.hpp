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
        http_proxy_client_session(asio::ip::tcp::socket&& ua_socket, asio::ip::tcp::socket&& _server_socket, std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count, std::weak_ptr< http_proxy_client_session_manager> in_session_manager);
        static std::shared_ptr<http_proxy_client_session> create(asio::ip::tcp::socket&& ua_socket, asio::ip::tcp::socket&& _server_socket,std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count, std::weak_ptr< http_proxy_client_session_manager> in_session_manager);
		void start() override;
		void on_server_connected() override;
		~http_proxy_client_session();
		void async_read_data_from_server(bool set_timer = true, std::size_t at_least_size = 1, std::size_t at_most_size = BUFFER_LENGTH) override;
		void async_send_data_to_server(const unsigned char* write_buffer, std::size_t offset, std::size_t size) override;
		void on_server_data_arrived(std::size_t bytes_transferred) override;
		void on_server_data_send(std::size_t bytes_transferred) override;
    private:
		std::weak_ptr< http_proxy_client_session_manager> _session_manager;
	protected:
		void close_connection();

	};
    
}

#pragma once
#include <array>
#include <chrono>
#include <memory>
#include <vector>

#include <asio.hpp>
using error_code = asio::error_code;
#include "http_proxy_connection.hpp"

namespace http_proxy
{
	class http_proxy_relay_connection : public http_proxy_connection
	{
	public:
		http_proxy_relay_connection(asio::io_context& in_io, std::shared_ptr<socket_wrapper> ua_socket, std::shared_ptr<socket_wrapper> _server_socket, std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count);

		static std::shared_ptr<http_proxy_relay_connection> create(asio::io_context& in_io, std::shared_ptr<socket_wrapper> ua_socket, std::shared_ptr<socket_wrapper> _server_socket, std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count);
		virtual void start() override;
		void on_server_connected() override;
	protected:
		virtual void on_server_data_arrived(std::size_t bytes_transferred) override;
		virtual void on_client_data_arrived(std::size_t bytes_transferred) override;
		virtual void on_client_data_send(std::size_t bytes_transferred) override;
		virtual void on_server_data_send(std::size_t bytes_transferred) override;

	};
}
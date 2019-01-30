#pragma once
#include <array>
#include <chrono>
#include <memory>
#include <vector>

#include <asio.hpp>
using error_code = asio::error_code;

#include "encrypt.hpp"
#include "http_header_parser.hpp"
#include "http_proxy_connection_context.hpp"

#include "http_proxy_connection.hpp"

namespace azure_proxy
{

	class http_proxy_client_connection : public http_proxy_connection
	{

	public:
		http_proxy_client_connection(asio::ip::tcp::socket&& ua_socket, asio::ip::tcp::socket&& _server_socket, std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count);
		virtual ~http_proxy_client_connection();
		static std::shared_ptr<http_proxy_client_connection> create(asio::ip::tcp::socket&& ua_socket, asio::ip::tcp::socket&& _server_socket,std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count);
		virtual void start();
		void on_server_connected();
	protected:
		virtual void on_server_data_arrived(std::size_t bytes_transferred) override;
		virtual void on_client_data_arrived(std::size_t bytes_transferred) override;
		virtual void on_client_data_send(std::size_t bytes_transferred) override;
		virtual void on_server_data_send(std::size_t bytes_transferred) override;

	};

} // namespace azure_proxy

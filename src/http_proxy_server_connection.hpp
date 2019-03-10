#pragma once

#include <array>
#include <chrono>

#include <asio.hpp>
using error_code = asio::error_code;

#include "encrypt.hpp"
#include "http_header_parser.hpp"
#include "http_proxy_connection_context.hpp"
#include "http_proxy_connection.hpp"

namespace azure_proxy {

class http_proxy_server_connection : public http_proxy_connection
{
protected:
	std::string modified_response_data;
	http_proxy_connection_context connection_context;
	http_proxy_server_connection_read_request_context read_request_context;
	http_proxy_server_connection_read_response_context read_response_context;
public:
	http_proxy_server_connection(asio::ip::tcp::socket&& in_client_socket, asio::ip::tcp::socket&& in_server_socket, std::shared_ptr<spdlog::logger> in_logger, std::uint32_t in_connection_count);
	~http_proxy_server_connection();

	static std::shared_ptr<http_proxy_server_connection> create(asio::ip::tcp::socket&& in_client_socket, asio::ip::tcp::socket&& in_server_socket, std::shared_ptr<spdlog::logger> in_logger, std::uint32_t in_connection_count);

	void start() override;
protected:
	void async_connect_to_server(std::string server_host, std::uint32_t server_port) override;
	void start_tunnel_transfer();
	void report_error(const std::string& status_code, const std::string& status_description, const std::string& error_message)override;
	void report_error(http_parser_result _parser_result) override;
	void report_authentication_failed();

	void on_resolved(asio::ip::tcp::resolver::iterator endpoint_iterator);
	void on_server_connected() override;
	void on_client_data_arrived(std::size_t bytes_transferred) override;
	void on_server_data_arrived(std::size_t bytes_transferred) override;
	void on_client_data_send(std::size_t bytes_transferred) override;
	void on_server_data_send(std::size_t bytes_transferred) override;
	void on_error(const error_code & error) override;
	void on_timeout(timer_type _cur_timer_type) override;
};

} // namespace azure_proxy

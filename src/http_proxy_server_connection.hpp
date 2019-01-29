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
	rsa rsa_pri;
	std::string modified_response_data;
	http_proxy_connection_context connection_context;
	http_proxy_server_connection_read_request_context read_request_context;
	http_proxy_server_connection_read_response_context read_response_context;

private:

	http_proxy_server_connection(asio::ip::tcp::socket&& client_socket, std::shared_ptr<spdlog::logger> in_logger, std::uint32_t in_connection_count);

	
public:
	~http_proxy_server_connection();

	static std::shared_ptr<http_proxy_server_connection> create(asio::ip::tcp::socket&& client_socket, std::shared_ptr<spdlog::logger> in_logger, std::uint32_t in_connection_count);

	void start();
private:
	void start_tunnel_transfer();
	void report_error(const std::string& status_code, const std::string& status_description, const std::string& error_message);
	void report_authentication_failed();

	void on_resolved(asio::ip::tcp::resolver::iterator endpoint_iterator);
};

} // namespace azure_proxy

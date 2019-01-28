/*
 *    http_proxy_server_connection.hpp:
 *
 *    Copyright (C) 2013-2015 limhiaoing <blog.poxiao.me> All Rights Reserved.
 *
 */

#ifndef AZURE_HTTP_PROXY_SERVER_CONNECTION_HPP
#define AZURE_HTTP_PROXY_SERVER_CONNECTION_HPP

#include <array>
#include <chrono>

#ifdef ASIO_STANDALONE
#include <asio.hpp>
using error_code = asio::error_code;

#else
#include <boost/asio.hpp>
namespace asio = boost::asio;
using error_code = boost::system::error_code;
#endif



#include "encrypt.hpp"
#include "http_header_parser.hpp"
#include "http_proxy_connection_context.hpp"

namespace azure_proxy {

class http_proxy_server_connection : public std::enable_shared_from_this<http_proxy_server_connection> {
	asio::io_service::strand strand;
	asio::ip::tcp::socket proxy_client_socket;
	asio::ip::tcp::socket origin_server_socket;
	asio::ip::tcp::resolver resolver;
	asio::basic_waitable_timer<std::chrono::steady_clock> timer;
	std::array<unsigned char, BUFFER_LENGTH> client_read_buffer;
	std::array<unsigned char, BUFFER_LENGTH> server_send_buffer;
	std::array<unsigned char, BUFFER_LENGTH> server_read_buffer;
	std::array<unsigned char, BUFFER_LENGTH> client_send_buffer;
	rsa rsa_pri;
	std::vector<unsigned char> encrypted_cipher_info;
	std::unique_ptr<stream_encryptor> encryptor;
	std::unique_ptr<stream_decryptor> decryptor;
	std::string modified_response_data;
	http_proxy_connection_context connection_context;
	http_proxy_server_connection_read_request_context read_request_context;
	http_proxy_server_connection_read_response_context read_response_context;
	std::shared_ptr<spdlog::logger> logger;
	http_request_parser _request_parser;
	http_response_parser _response_parser;
	const std::uint32_t connection_count;
	const std::string logger_prefix;
	decltype(std::chrono::system_clock::now()) _request_time;
private:

	http_proxy_server_connection(asio::ip::tcp::socket&& proxy_client_socket, std::shared_ptr<spdlog::logger> in_logger, std::uint32_t in_connection_count);

	
public:
	~http_proxy_server_connection();

	static std::shared_ptr<http_proxy_server_connection> create(asio::ip::tcp::socket&& client_socket, std::shared_ptr<spdlog::logger> in_logger, std::uint32_t in_connection_count);

	void start();
private:
	void async_read_data_from_client(std::size_t at_least_size = 1, std::size_t at_most_size = BUFFER_LENGTH);
	void async_read_data_from_server(bool set_timer = true, std::size_t at_least_size = 1, std::size_t at_most_size = BUFFER_LENGTH);
	void async_connect_to_origin_server();
	void async_send_data_to_server(const char* write_buffer, std::size_t offset, std::size_t size);
	void async_send_data_to_client(const char* write_buffer, std::size_t offset, std::size_t size);
	void start_tunnel_transfer();
	void report_error(const std::string& status_code, const std::string& status_description, const std::string& error_message);
	void report_authentication_failed();

	void set_timer();
	bool cancel_timer();

	void on_resolved(asio::ip::tcp::resolver::iterator endpoint_iterator);
	void on_server_connected();
	void on_client_data_arrived(std::size_t bytes_transferred);
	void on_server_data_arrived(std::size_t bytes_transferred);
	void on_client_data_send();
	void on_server_data_send();
	void on_error(const error_code& error);
	void on_timeout();
	bool try_set_security_info();
	void report_error(http_parser_result _status);
};

} // namespace azure_proxy

#endif

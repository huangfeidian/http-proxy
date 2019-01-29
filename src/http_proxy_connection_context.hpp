/*
 *    http_proxy_connection_context.hpp:
 *
 *    Copyright (C) 2013-2015 limhiaoing <blog.poxiao.me> All Rights Reserved.
 *
 */

#ifndef AZURE_http_proxy_connection_context_HPP
#define AZURE_http_proxy_connection_context_HPP

#include <cstdint>

#ifdef ASIO_STANDALONE
#include <asio.hpp>
using error_code = asio::error_code;

#else
#include <boost/asio.hpp>
namespace asio = boost::asio;
using error_code = boost::system::error_code;
#endif

#include "http_chunk_checker.hpp"

namespace azure_proxy {

enum class proxy_connection_state {
	ready,
	read_cipher_data,
	send_cipher_data,
	resolve_origin_server_address,
	connect_to_origin_server,
	tunnel_transfer,
	read_http_request_header,
	write_http_request_header,
	read_http_request_content,
	write_http_request_content,
	read_http_response_header,
	write_http_response_header,
	read_http_response_content,
	write_http_response_content,
	report_connection_established,
	report_error,
	resolve_proxy_server_address,
	connecte_to_proxy_server,
	session_tranfer,
};
enum class session_data_cmd
{
	authenticate,
	new_session,
	remove_session,
	session_data,
	ping_data,
	pong_data,
}
struct http_proxy_connection_context {
	proxy_connection_state connection_state;
	bool reconnect_on_error;
	std::string origin_server_name;
	unsigned short origin_server_port;
	std::unique_ptr<asio::ip::tcp::endpoint> origin_server_endpoint;
};

struct http_proxy_server_connection_read_request_context {
	bool is_proxy_client_keep_alive;
	std::uint32_t send_buffer_size;
};

struct http_proxy_server_connection_read_response_context {
	bool is_origin_server_keep_alive;
};

} // namespace azure_proxy

#endif

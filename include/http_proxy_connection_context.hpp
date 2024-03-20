#pragma once

#include <cstdint>
#include <unordered_map>
#include <vector>
#include <asio.hpp>
using error_code = asio::error_code;

#include "http_chunk_checker.hpp"

namespace http_proxy {

enum class proxy_connection_state {
	ready,
	read_cipher_data,
	send_cipher_data,
	resolve_server_address,
	connect_to_server,
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
};
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

enum class timer_type
{
	global_timer = 0,
	connect,
	resolve,
	up_send,
	up_read,
	down_read,
	down_send,
	max,
};
class timer_type_to_string
{
public:
	static std::string cast(timer_type _cur_type)
	{
		switch (_cur_type)
		{
		case http_proxy::timer_type::global_timer:
			return "global_timer";
			break;
		case http_proxy::timer_type::connect:
			return "connect";
			break;
		case http_proxy::timer_type::resolve:
			return "resolve";
			break;
		case http_proxy::timer_type::up_send:
			return "up_send";
			break;
		case http_proxy::timer_type::up_read:
			return "up_read";
			break;
		case http_proxy::timer_type::down_read:
			return "down_read";
			break;
		case http_proxy::timer_type::down_send:
			return "down_send";
			break;
		case http_proxy::timer_type::max:
			return "max";
			break;
		default:
			return "invalid";
			break;
		}
	}
};
} // namespace http_proxy

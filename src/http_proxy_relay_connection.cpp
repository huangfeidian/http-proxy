

#include <algorithm>
#include <cstring>
#include <utility>

#include "http_proxy_relay_config.hpp"
#include "http_proxy_relay_connection.hpp"
#include "key_generator.hpp"


namespace http_proxy
{
	http_proxy_relay_connection::http_proxy_relay_connection(asio::ip::tcp::socket&& ua_socket, asio::ip::tcp::socket&& _server_socket, std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count)
		: http_proxy_connection(std::move(ua_socket), std::move(_server_socket), logger, in_connection_count, http_proxy_relay_config::get_instance().get_timeout(), "", "relay_connection")
	{
		logger->info("{} new connection come from {}", logger_prefix, client_socket.remote_endpoint().address().to_string());
	}
	std::shared_ptr<http_proxy_relay_connection> http_proxy_relay_connection::create(asio::ip::tcp::socket && ua_socket, asio::ip::tcp::socket && _server_socket, std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count)
	{
		return std::make_shared<http_proxy_relay_connection>(std::move(ua_socket), std::move(_server_socket), logger, in_connection_count);
	}
	void http_proxy_relay_connection::start()
	{
		async_connect_to_server(http_proxy_relay_config::get_instance().get_proxy_server_address(), http_proxy_relay_config::get_instance().get_proxy_server_port());
	}
	void http_proxy_relay_connection::on_server_connected()
	{
		logger->info("{} connected to proxy server established", logger_prefix);

		this->async_read_data_from_client(false);
		this->async_read_data_from_server(false);
	}
	void http_proxy_relay_connection::on_client_data_arrived(std::size_t bytes_transferred)
	{
		logger->debug("{} on_client_data_arrived bytes_transferred {} hash_value {}", logger_prefix, bytes_transferred, aes_generator::checksum(client_read_buffer.data(), bytes_transferred));
		std::copy(client_read_buffer.data(), client_read_buffer.data() + bytes_transferred, server_send_buffer.data());
		async_send_data_to_server(server_send_buffer.data(), 0, bytes_transferred);
	}
	void http_proxy_relay_connection::on_server_data_arrived(std::size_t bytes_transferred)
	{
		logger->debug("{} on_server_data_arrived bytes_transferred {} hash_value {}", logger_prefix, bytes_transferred, aes_generator::checksum(server_read_buffer.data(), bytes_transferred));
		std::copy(server_read_buffer.data(), server_read_buffer.data() + bytes_transferred, client_send_buffer.data());
		async_send_data_to_client(client_send_buffer.data(), 0, bytes_transferred);
	}
	void http_proxy_relay_connection::on_client_data_send(std::size_t bytes_transferred)
	{
		async_read_data_from_server();
	}
	void http_proxy_relay_connection::on_server_data_send(std::size_t bytes_transferred)
	{
		async_read_data_from_client();
	}
}
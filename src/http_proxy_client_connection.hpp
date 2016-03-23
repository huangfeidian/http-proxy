/*
 *    http_proxy_client_connection.hpp:
 *
 *    Copyright (C) 2013-2015 limhiaoing <blog.poxiao.me> All Rights Reserved.
 *
 */

#ifndef AZURE_HTTP_PROXY_CLIENT_CONNECTION_HPP
#define AZURE_HTTP_PROXY_CLIENT_CONNECTION_HPP

#include <array>
#include <chrono>
#include <memory>
#include <vector>

#include "config.hpp"
#if ASIO_STANDALONE
#include <asio.hpp>
using error_code = asio::error_code;
#else
#include <boost/asio.hpp>
using error_code = boost::system::error_code
#endif
#include "encrypt.hpp"

const std::size_t BUFFER_LENGTH = 2048;

namespace azure_proxy
{

	class http_proxy_client_connection : public std::enable_shared_from_this < http_proxy_client_connection >
	{
		enum class proxy_connection_state
		{
			ready,
			resolve_proxy_server_address,
			connecte_to_proxy_server,
			tunnel_transfer
		};
	private:
		asio::io_service::strand strand;
		asio::ip::tcp::socket user_agent_socket;
		asio::ip::tcp::socket proxy_server_socket;
		asio::ip::tcp::resolver resolver;
		proxy_connection_state connection_state;
		asio::basic_waitable_timer<std::chrono::steady_clock> timer;
		std::vector<unsigned char> encrypted_cipher_info;
		std::array<char, BUFFER_LENGTH> upgoing_buffer_read;
		std::array<char, BUFFER_LENGTH> upgoing_buffer_write;
		std::array<char, BUFFER_LENGTH> downgoing_buffer_read;
		std::array<char, BUFFER_LENGTH> downgoing_buffer_write;
		std::unique_ptr<stream_encryptor> encryptor;
		std::unique_ptr<stream_decryptor> decryptor;
		std::chrono::seconds timeout;
	private:
		http_proxy_client_connection(asio::ip::tcp::socket&& ua_socket);
	public:
		~http_proxy_client_connection();
		static std::shared_ptr<http_proxy_client_connection> create(asio::ip::tcp::socket&& ua_socket);
		void start();
	private:
		void async_read_data_from_user_agent();
		void async_read_data_from_proxy_server(bool set_timer = true);
		void async_write_data_to_user_agent(const char* write_buffer, std::size_t offset, std::size_t size);
		void async_write_data_to_proxy_server(const char* write_buffer, std::size_t offset, std::size_t size);

		void set_timer();
		bool cancel_timer();

		void on_connection_established();
		void on_error(const asio::error_code& error);
		void on_timeout();
	};

} // namespace azure_proxy

#endif

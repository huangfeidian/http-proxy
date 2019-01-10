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
#include "http_proxy_server_connection_context.hpp"

#ifdef WITH_LOG
#include <fstream>

#endif

namespace azure_proxy
{

	class http_proxy_client_connection : public std::enable_shared_from_this < http_proxy_client_connection >
	{
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

		std::shared_ptr<spdlog::logger> logger;

		http_proxy_client_connection(asio::ip::tcp::socket&& ua_socket, std::shared_ptr<spdlog::logger> logger);
	private:
		// for trace use
		std::string request_data;
		std::string modified_request_data;
		std::string response_data;
		std::string modified_response_data;
		std::unique_ptr<http_request_header> request_header;
		std::unique_ptr<http_response_header> response_header;
		proxy_connection_state ua_up_connection_state;
		proxy_connection_state proxy_down_connection_state;
		http_proxy_server_connection_read_request_context read_request_context;
		http_proxy_server_connection_read_response_context read_response_context;
	public:
		~http_proxy_client_connection();
		static std::shared_ptr<http_proxy_client_connection> create(asio::ip::tcp::socket&& ua_socket, std::shared_ptr<spdlog::logger> logger);
		void start();
	private:
		void async_read_data_from_user_agent(std::size_t at_least_size = 1, std::size_t at_most_size = BUFFER_LENGTH);
		void async_read_data_from_proxy_server(bool set_timer = true, std::size_t at_least_size = 1, std::size_t at_most_size = BUFFER_LENGTH);
		void async_write_data_to_user_agent(const char* write_buffer, std::size_t offset, std::size_t size);
		void async_write_data_to_proxy_server(const char* write_buffer, std::size_t offset, std::size_t size);

		void set_timer();
		bool cancel_timer();

		void on_connection_established();
		void on_error(const error_code& error);
		void on_timeout();
	private:
		// for trace use
		void on_user_agent_data_arrived(std::size_t bytes_transfered);
		void on_proxy_server_data_arrived(std::size_t bytes_transfered);
		void async_write_header_to_proxy();
		void async_write_header_to_ua();
		void on_ua_up_data_written();
		void on_proxy_down_data_written();
		void report_error(const std::string& status_code, const std::string& status_description, const std::string& error_message);
	};

} // namespace azure_proxy

#endif

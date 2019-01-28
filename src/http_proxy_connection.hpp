/*
 *    http_proxy_client_connection.hpp:
 *
 *    Copyright (C) 2019-2021 spiritsaway.info All Rights Reserved.
 *
 */
#pragma once

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

#include "http_header_parser.hpp"
namespace azure_proxy
{

class http_proxy_connection : public std::enable_shared_from_this < http_proxy_connection>
	{
	private:
		asio::io_service::strand strand;
		asio::ip::tcp::socket client_socket;
		asio::ip::tcp::socket server_socket;
		asio::ip::tcp::resolver resolver;
		proxy_connection_state connection_state;
		asio::basic_waitable_timer<std::chrono::steady_clock> timer;
		std::vector<unsigned char> encrypted_cipher_info;
		std::array<char, MAX_HTTP_BUFFER_LENGTH> client_read_buffer;
		std::array<char, MAX_HTTP_BUFFER_LENGTH> server_send_buffer;
		std::array<char, MAX_HTTP_BUFFER_LENGTH> server_read_buffer;
		std::array<char, MAX_HTTP_BUFFER_LENGTH> client_send_buffer;
		std::unique_ptr<stream_encryptor> encryptor;
		std::unique_ptr<stream_decryptor> decryptor;
		std::chrono::seconds timeout;

		std::shared_ptr<spdlog::logger> logger;
		const std::uint32_t connection_count;
		const std::string logger_prefix;
		decltype(std::chrono::system_clock::now()) _request_time;
		http_proxy_connection(asio::ip::tcp::socket&& in_client_socket, asio::ip::tcp::socket&& in_server_socket, std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_idx, std::uint32_t in_timeout);
	private:

		// trace header
		http_request_parser _request_parser;
		http_response_parser _response_parser;
	public:
		virtual ~http_proxy_connection();
		static std::shared_ptr<http_proxy_connection> create(asio::ip::tcp::socket&& _in_client_socket, asio::ip::tcp::socket&& _in_server_socket, std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_idx, std::uint32_t _in_timeout);
		virtual void start();
	private:
		virtual void async_read_data_from_client(std::size_t at_least_size = 1, std::size_t at_most_size = BUFFER_LENGTH) = 0;
		virtual void async_read_data_from_server(bool set_timer = true, std::size_t at_least_size = 1, std::size_t at_most_size = BUFFER_LENGTH) = 0;
		virtual void async_send_data_to_client(std::size_t offset, std::size_t size) = 0;
		virtual void async_send_data_to_server(std::size_t offset, std::size_t size) = 0;
		virtual void async_connect_to_server(std::string server_ip, std::uint32_t server_port);
		void set_timer();
		bool cancel_timer();

		virtual void on_server_connected() = 0;
		virtual void on_error(const error_code& error) = 0;
		void on_timeout();
	private:
		// trace header
		virtual void on_client_data_arrived(std::size_t bytes_transfered) = 0;
		virtual void on_client_data_send(std::size_t bytes_transfered) = 0;
		virtual void on_server_data_arrived(std::size_t bytes_transfered) = 0;
		virtual void on_server_data_send(std::size_t bytes_transfered) = 0;
		void report_error(const std::string& status_code, const std::string& 
		status_description, const std::string& error_message);
		void close_connection();
		void report_error(http_parser_result _status);
	};

} // namespace azure_proxy
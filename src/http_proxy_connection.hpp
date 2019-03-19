#pragma once

#include <array>
#include <chrono>
#include <memory>
#include <vector>

#include <asio.hpp>
using error_code = asio::error_code;

#include <iostream>

#include <spdlog/spdlog.h>
#include "http_header_parser.hpp"
#include "http_proxy_connection_context.hpp"
#include "encrypt.hpp"


namespace azure_proxy
{

class http_proxy_connection : public std::enable_shared_from_this <http_proxy_connection>
	{

	protected:
		asio::io_service::strand strand;
		asio::ip::tcp::socket client_socket;
		asio::ip::tcp::socket server_socket;
		asio::ip::tcp::resolver resolver;
		proxy_connection_state connection_state;
		http_proxy_connection_context connection_context;
		std::vector<std::shared_ptr<asio::basic_waitable_timer<std::chrono::steady_clock>>> timers;
		std::vector<unsigned char> encrypted_cipher_info;
		std::array<unsigned char, MAX_HTTP_BUFFER_LENGTH> client_read_buffer;
		std::array<unsigned char, MAX_HTTP_BUFFER_LENGTH> server_send_buffer;
		std::array<unsigned char, MAX_HTTP_BUFFER_LENGTH> server_read_buffer;
		std::array<unsigned char, MAX_HTTP_BUFFER_LENGTH> client_send_buffer;
		std::unique_ptr<stream_encryptor> encryptor;
		std::unique_ptr<stream_decryptor> decryptor;
		std::chrono::seconds timeout;
		std::shared_ptr<spdlog::logger> logger;

		rsa rsa_key;
		decltype(std::chrono::system_clock::now()) _request_time;
	public:
		const std::uint32_t connection_count;
		const std::string logger_prefix;
		
	protected:

		// trace header
		http_request_parser _request_parser;
		http_response_parser _response_parser;
	public:
		virtual ~http_proxy_connection();
		static std::shared_ptr<http_proxy_connection> create(asio::ip::tcp::socket&& _in_client_socket, asio::ip::tcp::socket&& _in_server_socket, std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_idx, std::uint32_t _in_timeout, const std::string& rsa_key);
		http_proxy_connection(asio::ip::tcp::socket&& in_client_socket, asio::ip::tcp::socket&& in_server_socket, std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_idx, std::uint32_t in_timeout, const std::string& rsa_key, std::string log_pre = "connection");
		virtual void start();
	protected:
		virtual void async_read_data_from_client(bool set_timer = true, std::size_t at_least_size = 1, std::size_t at_most_size = BUFFER_LENGTH);
		virtual void async_read_data_from_server(bool set_timer = true, std::size_t at_least_size = 1, std::size_t at_most_size = BUFFER_LENGTH);
		virtual void async_send_data_to_client(const unsigned char* write_buffer, std::size_t offset, std::size_t size);
		virtual void async_send_data_to_client_impl(const unsigned char* write_buffer, std::size_t offset, std::size_t remain_size, std::size_t total_size);
		virtual void async_send_data_to_server(const unsigned char* write_buffer, std::size_t offset, std::size_t size);
		virtual void async_send_data_to_server_impl(const unsigned char* write_buffer, std::size_t offset, std::size_t remain_size, std::size_t total_size);
		virtual void async_connect_to_server(std::string server_ip, std::uint32_t server_port);
		void set_timer(timer_type _cur_timer);
		bool cancel_timer(timer_type _cur_timer);
		void cancel_all_timers();
		virtual void on_server_connected();
		virtual void on_resolved(asio::ip::tcp::resolver::iterator endpoint_iterator);
		virtual void on_error(const error_code& error);
		virtual void on_timeout(timer_type _cur_timer_type);
	protected:
		// trace header
		virtual void on_client_data_arrived(std::size_t bytes_transfered);
		virtual void on_client_data_send(std::size_t bytes_transfered);
		virtual void on_server_data_arrived(std::size_t bytes_transfered);
		virtual void on_server_data_send(std::size_t bytes_transfered);
		virtual void report_error(const std::string& status_code, const std::string& 
		status_description, const std::string& error_message);
		void close_connection();
		virtual void report_error(http_parser_result _status);
		bool init_cipher(const std::string& cipher_name, const std::string& rsa_pub);
		bool accept_cipher(const unsigned char* cipher_data, std::size_t cipher_size);
	public:
		friend class http_proxy_session_manager;
	};

} // namespace azure_proxy
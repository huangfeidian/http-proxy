

#include <algorithm>
#include <cstring>
#include <utility>

#include "http_proxy_client_config.hpp"
#include "http_proxy_client_connection.hpp"
#include "http_proxy_client_stat.hpp"
#include "key_generator.hpp"


namespace http_proxy
{

	http_proxy_client_connection::http_proxy_client_connection(asio::io_context& in_io, std::shared_ptr<socket_wrapper> ua_socket, std::shared_ptr<socket_wrapper> server_socket, std::shared_ptr<spdlog::logger> in_logger, std::uint32_t in_connection_count, std::string log_pre):
	http_proxy_connection(in_io, std::move(ua_socket), std::move(server_socket), in_logger, in_connection_count, http_proxy_client_config::get_instance().get_timeout(), http_proxy_client_config::get_instance().get_rsa_public_key(), log_pre)
	{
		_request_time = std::chrono::system_clock::now();
		http_proxy_client_stat::get_instance().increase_current_connections();
		logger->info("{} new connection come! total connection count {}", logger_prefix, http_proxy_client_stat::get_instance().get_current_connections());
	}

	http_proxy_client_connection::~http_proxy_client_connection()
	{
		http_proxy_client_stat::get_instance().decrease_current_connections();
	}

	std::shared_ptr<http_proxy_client_connection> http_proxy_client_connection::create(asio::io_context& in_io, std::shared_ptr<socket_wrapper> ua_socket, std::shared_ptr<socket_wrapper> _server_socket,std::shared_ptr<spdlog::logger> in_logger, std::uint32_t in_connection_count)
	{
		return std::make_shared<http_proxy_client_connection>(in_io, std::move(ua_socket), std::move(_server_socket), in_logger,  in_connection_count);
	}
	
	void http_proxy_client_connection::start()
	{

		if(!init_cipher(http_proxy_client_config::get_instance().get_cipher(), http_proxy_client_config::get_instance().get_rsa_public_key()))
		{
			logger->warn("{} fail to start client connection init_cipher fail", logger_prefix);
			return;
		}
		async_connect_to_server(http_proxy_client_config::get_instance().get_proxy_server_address(), http_proxy_client_config::get_instance().get_proxy_server_port());
		
	}


	void http_proxy_client_connection::on_server_connected()
	{
		logger->info("{} connected to proxy server established", logger_prefix);
		std::copy(encrypted_cipher_info.begin(), encrypted_cipher_info.end(), server_send_buffer.data());
		this->async_send_data_to_server(server_send_buffer.data(), 0, this->encrypted_cipher_info.size());
		this->async_read_data_from_server(false);
	}


	void http_proxy_client_connection::on_server_data_arrived(std::size_t bytes_transferred)
	{
		http_proxy_client_stat::get_instance().on_downgoing_recv(static_cast<std::uint32_t>(bytes_transferred));
		logger->debug("{} before decrypt hash is {}", logger_prefix, aes_generator::checksum(server_read_buffer.data(), bytes_transferred));
		this->decryptor->decrypt(server_read_buffer.data(), client_send_buffer.data(), bytes_transferred);
		
		logger->debug("{} decrypt server data size {} hash value {}", logger_prefix, bytes_transferred, aes_generator::checksum(client_send_buffer.data(), bytes_transferred));
		logger->trace("{} data is {}", logger_prefix, std::string_view(reinterpret_cast<const char*>(client_send_buffer.data()), bytes_transferred));

		logger->debug("{} on_server_data_arrived bytes {}", logger_prefix, bytes_transferred);
		if (connection_state == proxy_connection_state::tunnel_transfer)
		{
			this->async_send_data_to_client(client_send_buffer.data(), 0, bytes_transferred);
			return;
		}
		if (!_response_parser.append_input(client_send_buffer.data(), bytes_transferred))
		{
			report_error("400", "Bad request", "buffer overflow");
			return;
		}
		std::uint32_t send_buffer_size = 0;
		while (true)
		{
			auto cur_parse_result = _response_parser.parse();
			if (cur_parse_result.first >= http_parser_result::parse_error)
			{
				report_error(cur_parse_result.first);
				return;
			}
			else if (cur_parse_result.first == http_parser_result::read_one_header)
			{
				auto cur_header_counter = _response_parser._header.get_header_value("header_counter");
				if (cur_header_counter)
				{
					logger->info("request {0} back", cur_header_counter.value());
				}
				_response_parser._header.erase_header("header_counter");
				if (_request_parser._header.method() == "CONNECT" && _response_parser._header.status_code() == 200)
				{
					connection_state = proxy_connection_state::tunnel_transfer;
				}
				auto header_data = _response_parser._header.encode_to_data();
				//logger->trace("{} read proxy response header data {}", logger_prefix, header_data);
				std::copy(header_data.begin(), header_data.end(), client_send_buffer.data() + send_buffer_size);
				send_buffer_size += header_data.size();
				auto _response_time = std::chrono::system_clock::now();
				std::chrono::duration<double> elapsed_seconds = _response_time - _request_time;
				if (elapsed_seconds.count() > 0.5)
				{
					logger->warn("{} response for host {} cost {} seconds", logger_prefix, _request_parser._header.host(), elapsed_seconds.count());
				}
				_request_parser.reset_header();

			}
			else if (cur_parse_result.first == http_parser_result::read_some_content)
			{
				std::copy(cur_parse_result.second.begin(), cur_parse_result.second.end(), client_send_buffer.data() + send_buffer_size);
				send_buffer_size += cur_parse_result.second.size();
			}
			else if(cur_parse_result.first == http_parser_result::read_content_end)
			{
				_response_parser.reset_header();
				std::copy(cur_parse_result.second.begin(), cur_parse_result.second.end(), client_send_buffer.data() + send_buffer_size);
				send_buffer_size += cur_parse_result.second.size();
			}
			else
			{
				break;
			}

		}
		if (send_buffer_size)
		{
			this->async_send_data_to_client(client_send_buffer.data(), 0, send_buffer_size);
		}
		else
		{
			async_read_data_from_server();
		}
		
	}
	void http_proxy_client_connection::on_client_data_arrived(std::size_t bytes_transferred)
	{
		http_proxy_client_stat::get_instance().on_upgoing_recv(static_cast<std::uint32_t>(bytes_transferred));
		logger->debug("{} on_client_data_arrived size {}", logger_prefix, bytes_transferred);
		//logger->trace("{} data is {}", logger_prefix, std::string(client_read_buffer.data(), client_read_buffer.data() + bytes_transferred));
		static std::atomic<uint32_t> header_counter = 0;
		if (connection_state == proxy_connection_state::tunnel_transfer)
		{
			logger->debug("{} encrypt data size {} hash value {}", logger_prefix, bytes_transferred, aes_generator::checksum(client_read_buffer.data(), bytes_transferred));
			logger->trace("{} data is {}", logger_prefix, std::string_view(reinterpret_cast<const char*>(client_read_buffer.data()), bytes_transferred));
			encryptor->encrypt(client_read_buffer.data(), server_send_buffer.data(), bytes_transferred);
			logger->debug("{} after encrypt  hash value {}", logger_prefix, aes_generator::checksum(server_send_buffer.data(), bytes_transferred));
			async_send_data_to_server(server_send_buffer.data(), 0, bytes_transferred);
			return;

		}
		if (!_request_parser.append_input(client_read_buffer.data(), bytes_transferred))
		{
			report_error("400", "Bad request", "buffer overflow");
			return;
		}
		std::uint32_t send_buffer_size = 0;
		while (true)
		{
			auto cur_parse_result = _request_parser.parse();
			//logger->trace("{} after one parse status is {}", logger_prefix, _http_request_parser.status());
			if (cur_parse_result.first >= http_parser_result::parse_error)
			{
				report_error(cur_parse_result.first);
				return;
			}
			else if (cur_parse_result.first == http_parser_result::read_one_header)
			{
				_request_parser._header.set_header_counter(std::to_string(header_counter++));
				auto header_data = _request_parser._header.encode_to_data();
				//logger->trace("{} read ua request header data {}", logger_prefix, header_data);
				std::copy(header_data.begin(), header_data.end(), server_send_buffer.data() + send_buffer_size);
				send_buffer_size += header_data.size();
				_request_time = std::chrono::system_clock::now();
			}
			else if (cur_parse_result.first == http_parser_result::read_some_content)
			{
				std::copy(cur_parse_result.second.begin(), cur_parse_result.second.end(), server_send_buffer.data() + send_buffer_size);
				send_buffer_size += cur_parse_result.second.size();
			}
			else if(cur_parse_result.first == http_parser_result::read_content_end)
			{
				std::copy(cur_parse_result.second.begin(), cur_parse_result.second.end(), server_send_buffer.data() + send_buffer_size);
				send_buffer_size += cur_parse_result.second.size();
			}
			else
			{
				break;
			}

		}
		if (send_buffer_size)
		{
			logger->debug("{} encrypt data size {} hash value {}", logger_prefix, send_buffer_size, aes_generator::checksum(server_send_buffer.data(), send_buffer_size));
			logger->trace("{} data is {}", logger_prefix, std::string_view(reinterpret_cast<const char*>(server_send_buffer.data()), send_buffer_size));
			encryptor->transform(server_send_buffer.data(), send_buffer_size, 256);
			logger->debug("{} after encrypt  hash value {}", logger_prefix, aes_generator::checksum(server_send_buffer.data(), send_buffer_size));

			this->async_send_data_to_server(server_send_buffer.data(), 0, send_buffer_size);
		}
		else
		{
			async_read_data_from_client();
		}
		
	}
	void http_proxy_client_connection::on_client_data_send(std::size_t bytes_transferred)
	{
		async_read_data_from_server();
	}
	void http_proxy_client_connection::on_server_data_send(std::size_t bytes_transferred)
	{
		async_read_data_from_client();
	}
} // namespace http_proxy

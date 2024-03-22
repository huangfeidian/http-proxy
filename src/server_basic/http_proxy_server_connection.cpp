#include <cctype>
#include <algorithm>
#include <cassert>
#include <cstring>

#include <asio.hpp>
using error_code = asio::error_code;

#include "authentication.hpp"
#include "http_proxy_server_config.hpp"
#include "http_proxy_server_connection.hpp"




namespace http_proxy
{

	http_proxy_server_connection::http_proxy_server_connection(asio::io_context& in_io, std::shared_ptr<socket_wrapper> in_client_socket, std::shared_ptr<socket_wrapper> in_server_socket,std::shared_ptr<spdlog::logger> in_logger, std::uint32_t _connection_count, std::string log_pre):
	http_proxy_connection(in_io, std::move(in_client_socket), std::move(in_server_socket), in_logger, _connection_count, http_proxy_server_config::get_instance().get_timeout(), http_proxy_server_config::get_instance().get_rsa_private_key(), log_pre)
	{

	}

	http_proxy_server_connection::~http_proxy_server_connection()
	{

	}

	std::shared_ptr<http_proxy_server_connection> http_proxy_server_connection::create(asio::io_context& in_io, std::shared_ptr<socket_wrapper> in_client_socket, std::shared_ptr<socket_wrapper> in_server_socket, std::shared_ptr<spdlog::logger> in_logger, std::uint32_t connection_count)
	{
		return std::make_shared<http_proxy_server_connection>(in_io, std::move(in_client_socket), std::move(in_server_socket), in_logger, connection_count);
	}

	void http_proxy_server_connection::start()
	{
		this->connection_context.connection_state = proxy_connection_state::read_cipher_data;
		this->async_read_data_from_client(true);
		logger->info("{} new connection start", logger_prefix);
	}




	void http_proxy_server_connection::async_connect_to_server(std::string server_host, std::uint32_t server_port)
	{
		this->connection_context.reconnect_on_error = false;
		if (_request_parser._header.method() == "CONNECT")
		{
			this->server_socket->shutdown();
		}

		if (this->server_socket->is_open() &&
			server_host == this->connection_context.origin_server_name &&
			server_port == this->connection_context.origin_server_port)
		{
			this->connection_context.reconnect_on_error = true;
			this->on_server_connected();
		}
		else
		{
			if(this->server_socket->is_open())
			{
				this->server_socket->shutdown();
			}
			this->connection_context.origin_server_name = server_host;
			this->connection_context.origin_server_port = server_port;

			this->connection_context.connection_state = proxy_connection_state::resolve_server_address;
			logger->info("{} connect to {}:{}", logger_prefix, server_host, server_port);
			this->server_socket->async_connect(server_host, server_port);
		}
	}

	

	void http_proxy_server_connection::start_tunnel_transfer()
	{
		logger->info("{} start tunnel transfer ", logger_prefix);
		this->connection_context.connection_state = proxy_connection_state::tunnel_transfer;
		this->async_read_data_from_client();
		this->async_read_data_from_server(false);
	}

	void http_proxy_server_connection::report_error(const std::string& status_code, const std::string& status_description, const std::string& error_message)
	{
		logger->warn("{} report error status_code {} status_description {} error_message {}", logger_prefix, status_code, status_description, error_message);
		this->modified_response_data.clear();
		this->modified_response_data += "HTTP/1.1 ";
		this->modified_response_data += status_code;
		if (!status_description.empty())
		{
			this->modified_response_data.push_back(' ');
			this->modified_response_data += status_description;
		}
		this->modified_response_data += "\r\n";
		this->modified_response_data += "Content-Type: text/html\r\n";
		this->modified_response_data += "Server: HttpProxy\r\n";
		this->modified_response_data += "Content-Length: ";

		std::string response_content;
		response_content = "<!DOCTYPE html><html><head><title>";
		response_content += status_code;
		response_content += ' ';
		response_content += status_description;
		response_content += "</title></head><body bgcolor=\"white\"><center><h1>";
		response_content += status_code;
		response_content += ' ';
		response_content += status_description;
		response_content += "</h1>";
		if (!error_message.empty())
		{
			response_content += "<br/>";
			response_content += error_message;
			response_content += "</center>";
		}
		response_content += "<hr><center>";
		response_content += "Http Proxy server";
		response_content += "</center></body></html>";
		this->modified_response_data += std::to_string(response_content.size());
		this->modified_response_data += "\r\n";
		this->modified_response_data += "Proxy-Connection: close\r\n";
		this->modified_response_data += "\r\n";
		if (_request_parser._header.method() != "HEAD")
		{
			this->modified_response_data += response_content;
		}
		if(this->encryptor)
		{
			this->encryptor->transform(reinterpret_cast<unsigned char*>(&modified_response_data[0]), modified_response_data.size(), 16);
		}
		
		this->connection_context.connection_state = proxy_connection_state::report_error;
		auto self(this->shared_from_this());
		this->async_send_data_to_client(reinterpret_cast<unsigned char*>(this->modified_response_data.data()), 0, this->modified_response_data.size());
	}
	void http_proxy_server_connection::report_error(http_parser_result _parser_result)
	{
		auto error_detail = from_praser_result_to_description(_parser_result);
		report_error(std::to_string(std::get<0>(error_detail)), std::get<1>(error_detail), std::get<2>(error_detail));
	}

	void http_proxy_server_connection::report_authentication_failed()
	{
		logger->warn("{} report_authentication_failed with info {}", logger_prefix, _request_parser._header.proxy_authorization());
		std::string content = "<!DOCTYPE html><html><head><title>407 Proxy Authentication Required</title></head>";
		content += "<body bgcolor=\"white\"><center><h1>407 Proxy Authentication Required</h1></center><hr><center>Http Proxy server</center></body></html>";
		this->modified_response_data = "HTTP/1.1 407 Proxy Authentication Required\r\n";
		this->modified_response_data += "Server: HttpProxy\r\n";
		this->modified_response_data += "Proxy-Authenticate: Basic realm=\"HttpProxy\"\r\n";
		this->modified_response_data += "Content-Type: text/html\r\n";
		this->modified_response_data += "Connection: Close\r\n";
		this->modified_response_data += "Content-Length: ";
		this->modified_response_data += std::to_string(content.size());
		this->modified_response_data += "\r\n\r\n";
		this->modified_response_data += content;
		this->encryptor->transform(reinterpret_cast<unsigned char*>(&modified_response_data[0]), modified_response_data.size(), 16);
		this->connection_context.connection_state = proxy_connection_state::report_error;
		this->async_send_data_to_client(reinterpret_cast<unsigned char*>(this->modified_response_data.data()), 0, this->modified_response_data.size());
	}

	void http_proxy_server_connection::on_server_connected()
	{
		logger->info("{} connect to server {} suc method {}", logger_prefix, _request_parser._header.host(), _request_parser._header.method());
		if (_request_parser._header.method() == "CONNECT")
		{
			const unsigned char response_message[] = "HTTP/1.1 200 Connection Established\r\nConnection: Close\r\n\r\n";
			this->modified_response_data.resize(sizeof(response_message) - 1);
			this->encryptor->encrypt(response_message, reinterpret_cast<unsigned char*>(&this->modified_response_data[0]), this->modified_response_data.size());
			this->connection_context.connection_state = proxy_connection_state::report_connection_established;
			this->async_send_data_to_client(reinterpret_cast<unsigned char*>(&this->modified_response_data[0]), 0, this->modified_response_data.size());
		}
		else
		{
			logger->info("{} send request to origin server method {} resource {} header_counter {}", logger_prefix, this->_request_parser._header.method(), this->_request_parser._header.path_and_query(), this->_request_parser._header.get_header_counter());
			this->connection_context.connection_state = proxy_connection_state::write_http_request_header;
			this->async_send_data_to_server(server_send_buffer.data(), 0, read_request_context.send_buffer_size);
		}
	}

	void http_proxy_server_connection::on_client_data_arrived(std::size_t bytes_transferred)
	{
		logger->debug("{} on_client_data_arrived size {} proxy_connection_state {}", logger_prefix, bytes_transferred, int(connection_context.connection_state));
		
		if (this->connection_context.connection_state == proxy_connection_state::read_cipher_data)
		{
			std::copy(this->client_read_buffer.begin(), this->client_read_buffer.begin() + bytes_transferred, std::back_inserter(this->encrypted_cipher_info));
			if(encrypted_cipher_info.size() < rsa_key.modulus_size())
			{
				this->async_read_data_from_client(true);
				return;
			}
			if (!accept_cipher(encrypted_cipher_info.data(), encrypted_cipher_info.size()))
			{
				logger->warn("{} invalid security info connection fail", logger_prefix);
				report_error("501", "Bad Request", "security info fail");
				return;

			}
			this->connection_context.connection_state = proxy_connection_state::read_http_request_header;
			this->async_read_data_from_client();
			logger->info("{} security info set begin to chat", logger_prefix);
			return;
		}
		assert(this->encryptor != nullptr && this->decryptor != nullptr);
		logger->debug("{} before decrypt hash is {}", logger_prefix, aes_generator::checksum(client_read_buffer.data(), bytes_transferred));
		this->decryptor->decrypt(client_read_buffer.data(), server_send_buffer.data(), bytes_transferred);
		logger->debug("{} decrypt client data size {} hash {}", logger_prefix, bytes_transferred, aes_generator::checksum(server_send_buffer.data(), bytes_transferred));
		logger->trace("{} data is {}", logger_prefix, std::string_view(reinterpret_cast<const char*>(server_send_buffer.data()), bytes_transferred));
		if (this->connection_context.connection_state == proxy_connection_state::tunnel_transfer)
		{
			this->async_send_data_to_server(server_send_buffer.data(), 0, bytes_transferred);
			return;
		}
		if (!_request_parser.append_input(server_send_buffer.data(), bytes_transferred))
		{
			report_error("400", "Bad Request", "buffer overflow");
		}
		
		std::uint32_t send_buffer_size = 0;
		read_request_context.send_buffer_size = 0;
		bool header_readed = false;
		while (true)
		{
			auto cur_parse_result = _request_parser.parse();
			if (cur_parse_result.first >= http_parser_result::parse_error)
			{
				report_error(cur_parse_result.first);
				return;
			}
			else if (cur_parse_result.first == http_parser_result::read_one_header)
			{
				_request_time = std::chrono::system_clock::now();
				auto cur_header_counter = _request_parser._header.get_header_value("header_counter");
				if (cur_header_counter)
				{
					logger->info("{} request {} reach server host {} path {}", logger_prefix, cur_header_counter.value(), _request_parser._header.host(), _request_parser._header.path_and_query());
				}
				if (http_proxy_server_config::get_instance().enable_auth())
				{
					const auto& proxy_authorization_value = _request_parser._header.proxy_authorization();
					bool auth_success = false;
					if (!proxy_authorization_value.empty())
					{
						if (authentication::get_instance().auth(proxy_authorization_value) == auth_result::ok)
						{
							auth_success = true;
						}
					}
					if (!auth_success)
					{
						this->report_authentication_failed();
						return;
					}
				}
				header_readed = true;
				auto header_data = _request_parser._header.encode_to_data();
				logger->trace("{} read client request header {}", logger_prefix, header_data);
				std::copy(header_data.begin(), header_data.end(), server_send_buffer.data() + send_buffer_size);
				send_buffer_size += header_data.size();
				this->read_request_context.is_proxy_client_keep_alive = _request_parser._header.is_keep_alive();
			}
			else if (cur_parse_result.first == http_parser_result::read_some_content)
			{
				std::copy(cur_parse_result.second.begin(), cur_parse_result.second.end(), server_send_buffer.data() + send_buffer_size);
				send_buffer_size += cur_parse_result.second.size();
			}
			else if (cur_parse_result.first == http_parser_result::read_content_end)
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
			if (header_readed)
			{
				if (_request_parser._header.method() == "connect")
				{
					async_connect_to_server(_request_parser._header.host(), _request_parser._header.port());
					return;
				}
				else
				{
					read_request_context.send_buffer_size = send_buffer_size;
					async_connect_to_server(_request_parser._header.host(), _request_parser._header.port());
					return;
				}
			}
			else
			{
				async_send_data_to_server(server_send_buffer.data(), 0, send_buffer_size);
			}
		}
		else
		{
			async_read_data_from_client();
		}
		
	}

	void http_proxy_server_connection::on_server_data_arrived(std::size_t bytes_transferred)
	{
		logger->debug("{} on_server_data_arrived size {}", logger_prefix, bytes_transferred);
		if (this->connection_context.connection_state == proxy_connection_state::tunnel_transfer)
		{
			logger->debug("{} encrypt origin server data size {} hash {}", logger_prefix, bytes_transferred, aes_generator::checksum(server_read_buffer.data(), bytes_transferred));
			logger->trace("{} data is {}", logger_prefix, std::string_view(reinterpret_cast<const char*>(server_read_buffer.data()), bytes_transferred));
			this->encryptor->encrypt(server_read_buffer.data(), client_send_buffer.data(), bytes_transferred);
			logger->debug("{} after encrypt hash is {}", logger_prefix, aes_generator::checksum(client_send_buffer.data(), bytes_transferred));
			this->async_send_data_to_client(client_send_buffer.data(), 0, bytes_transferred);
			return;
		}
		if (!_response_parser.append_input(server_read_buffer.data(), bytes_transferred))
		{
			this->report_error("400", "Bad Request", "Buffer overflow");
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
				auto is_keep_alive = _response_parser._header.is_keep_alive();
				if (!is_keep_alive)
				{
					report_error("400", "Bad Request", "invalid Connection value");
					return;
				}
				read_response_context.is_origin_server_keep_alive = is_keep_alive.value();
				auto header_data = _response_parser._header.encode_to_data();
				logger->trace("{} read server response header {}", logger_prefix, header_data);
				std::copy(header_data.begin(), header_data.end(), client_send_buffer.data() + send_buffer_size);
				send_buffer_size += header_data.size();
				this->connection_context.connection_state = proxy_connection_state::write_http_response_header;
				auto _response_time = std::chrono::system_clock::now();
				std::chrono::duration<double> elapsed_seconds = _response_time - _request_time;
				if (elapsed_seconds.count() > 0.5)
				{
					logger->warn("{} response for host {} cost {} seconds", logger_prefix, _request_parser._header.host(), elapsed_seconds.count());
				}
			}
			else if (cur_parse_result.first == http_parser_result::read_some_content)
			{
				this->connection_context.connection_state = proxy_connection_state::write_http_response_content;
				std::copy(cur_parse_result.second.begin(), cur_parse_result.second.end(), client_send_buffer.data() + send_buffer_size);
				send_buffer_size += cur_parse_result.second.size();

			}
			else if(cur_parse_result.first == http_parser_result::read_content_end)
			{
				this->connection_context.connection_state = proxy_connection_state::write_http_response_content;
				_response_parser.reset_header();
				_request_parser.reset_header();
				//logger->trace("{} read server response content {}", logger_prefix, cur_parse_result.second);
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
			logger->debug("{} encrypt origin server data size {} hash {}", logger_prefix, send_buffer_size, aes_generator::checksum(client_send_buffer.data(), send_buffer_size));
			logger->trace("{} data is {}", logger_prefix, std::string_view(reinterpret_cast<const char*>(client_send_buffer.data()), send_buffer_size));
			this->encryptor->encrypt(client_send_buffer.data(), client_send_buffer.data(), send_buffer_size);
			logger->debug("{} after encrypt hash is {}", logger_prefix, aes_generator::checksum(client_send_buffer.data(), bytes_transferred));
			this->async_send_data_to_client(this->client_send_buffer.data(), 0, send_buffer_size);
		}
		else
		{
			async_read_data_from_server();
		}
		
	}

	void http_proxy_server_connection::on_client_data_send(std::size_t bytes_transferred)
	{
		if (this->connection_context.connection_state == proxy_connection_state::tunnel_transfer)
		{
			this->async_read_data_from_server();
		}
		else if (this->connection_context.connection_state == proxy_connection_state::write_http_response_header
				 || this->connection_context.connection_state == proxy_connection_state::write_http_response_content)
		{
			if (_response_parser.status() == http_parser_status::read_header)
			{
				error_code ec;
				if (!this->read_response_context.is_origin_server_keep_alive)
				{
					this->server_socket->shutdown();
				}
				if (this->read_request_context.is_proxy_client_keep_alive)
				{
					this->connection_context.connection_state = proxy_connection_state::read_http_request_header;
					this->async_read_data_from_client();
				}
				else
				{
					this->client_socket->shutdown();
				}
			}
			else
			{
				this->connection_context.connection_state = proxy_connection_state::read_http_response_content;
				this->async_read_data_from_server();
			}
		}
		else if (this->connection_context.connection_state == proxy_connection_state::report_connection_established)
		{
			this->start_tunnel_transfer();
		}
		else if (this->connection_context.connection_state == proxy_connection_state::report_error)
		{
			close_connection();
		}
	}

	void http_proxy_server_connection::on_server_data_send(std::size_t bytes_transferred)
	{
		if (this->connection_context.connection_state == proxy_connection_state::tunnel_transfer)
		{
			this->async_read_data_from_client();
		}
		else if (this->connection_context.connection_state == proxy_connection_state::write_http_request_header
				 || this->connection_context.connection_state == proxy_connection_state::write_http_request_content)
		{
			if (_request_parser.status() == http_parser_status::read_header)
			{
				this->connection_context.connection_state = proxy_connection_state::read_http_response_header;
				this->async_read_data_from_server();
			}
			else
			{
				this->connection_context.connection_state = proxy_connection_state::read_http_request_content;
				this->async_read_data_from_client();
			}
		}
	}

	void http_proxy_server_connection::on_error(const error_code& error)
	{
		if (this->connection_context.connection_state == proxy_connection_state::resolve_server_address)
		{
			this->report_error("504", "Gateway Timeout", "Failed to resolve the hostname");
		}
		else if (this->connection_context.connection_state == proxy_connection_state::connect_to_server)
		{
			this->report_error("502", "Bad Gateway", "Failed to connect to origin server");
		}
		else if (this->connection_context.connection_state == proxy_connection_state::write_http_request_header && this->connection_context.reconnect_on_error)
		{
			logger->warn("{} reconnect to origin server by error", logger_prefix);
			server_socket->shutdown();
			this->async_connect_to_server(_request_parser._header.host(), _request_parser._header.port());
		}
		else
		{
			logger->warn("{} shutdown connections by error {}", logger_prefix, error.message());
			error_code ec;
			close_connection();
		}
	}

	void http_proxy_server_connection::on_timeout(timer_type _cur_timer_type)
	{
		logger->info("{} on_timeout for timer {}", logger_prefix, static_cast<uint32_t>(_cur_timer_type));
		close_connection();
	}


} // namespace http_proxy

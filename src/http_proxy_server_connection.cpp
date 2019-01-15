/*
*    http_proxy_server_connection.cpp:
*
*    Copyright (C) 2013-2015 limhiaoing <blog.poxiao.me> All Rights Reserved.
*
*/

#include <cctype>
#include <algorithm>
#include <cassert>
#include <cstring>

#include "authentication.hpp"
#include "http_proxy_server_config.hpp"
#include "http_proxy_server_connection.hpp"
#ifdef ASIO_STANDALONE
#include <asio.hpp>
using error_code = asio::error_code;

#else
#include <boost/asio.hpp>
namespace asio = boost::asio;
using error_code = boost::system::error_code;
#endif

namespace azure_proxy
{

	http_proxy_server_connection::http_proxy_server_connection(asio::ip::tcp::socket&& proxy_client_socket, std::shared_ptr<spdlog::logger> in_logger, std::uint32_t _connection_count) :
		strand(proxy_client_socket.get_io_service()),
		proxy_client_socket(std::move(proxy_client_socket)),
		origin_server_socket(this->proxy_client_socket.get_io_service()),
		resolver(this->proxy_client_socket.get_io_service()),
		timer(this->proxy_client_socket.get_io_service()),
		rsa_pri(http_proxy_server_config::get_instance().get_rsa_private_key()),
		logger(in_logger),
		connection_count(_connection_count),
		logger_prefix("connection " + std::to_string(connection_count) + ": ")
	{
		this->connection_context.connection_state = proxy_connection_state::read_cipher_data;
	}

	http_proxy_server_connection::~http_proxy_server_connection()
	{}

	std::shared_ptr<http_proxy_server_connection> http_proxy_server_connection::create(asio::ip::tcp::socket&& client_socket, std::shared_ptr<spdlog::logger> in_logger, std::uint32_t connection_count)
	{
		return std::shared_ptr<http_proxy_server_connection>(new http_proxy_server_connection(std::move(client_socket), in_logger, connection_count));
	}

	void http_proxy_server_connection::start()
	{
		this->connection_context.connection_state = proxy_connection_state::read_cipher_data;
		this->async_read_data_from_proxy_client(1, std::min<std::size_t>(this->rsa_pri.modulus_size(), BUFFER_LENGTH));
		logger->info("{} new connection start", logger_prefix);
	}

	void http_proxy_server_connection::async_read_data_from_proxy_client(std::size_t at_least_size, std::size_t at_most_size)
	{
		assert(at_least_size <= at_most_size && at_most_size <= BUFFER_LENGTH);
		auto self(this->shared_from_this());
		this->set_timer();
		asio::async_read(this->proxy_client_socket,
								asio::buffer(&this->upgoing_buffer_read[0], at_most_size),
								asio::transfer_at_least(at_least_size),
								this->strand.wrap([this, self](const error_code& error, std::size_t bytes_transferred)
		{
			if (this->cancel_timer())
			{
				if (!error)
				{
					this->on_proxy_client_data_arrived(bytes_transferred);
				}
				else
				{
					this->on_error(error);
				}
			}
		})
								);
	}

	void http_proxy_server_connection::async_read_data_from_origin_server(bool set_timer, std::size_t at_least_size, std::size_t at_most_size)
	{
		auto self(this->shared_from_this());
		if (set_timer)
		{
			this->set_timer();
		}
		asio::async_read(this->origin_server_socket,
								asio::buffer(&this->downgoing_buffer_read[0], at_most_size),
								asio::transfer_at_least(at_least_size),
								this->strand.wrap([this, self](const error_code& error, std::size_t bytes_transferred)
		{
			if (this->cancel_timer())
			{
				if (!error)
				{
					this->on_origin_server_data_arrived(bytes_transferred);
				}
				else
				{
					this->on_error(error);
				}
			}
		})
								);
	}

	void http_proxy_server_connection::async_connect_to_origin_server()
	{
		this->connection_context.reconnect_on_error = false;
		if (this->origin_server_socket.is_open())
		{
			if (_request_parser._header.method() == "CONNECT")
			{
				error_code ec;
				this->origin_server_socket.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
				this->origin_server_socket.close(ec);
			}
		}

		if (this->origin_server_socket.is_open() &&
			this->_request_parser._header.host() == this->connection_context.origin_server_name &&
			this->_request_parser._header.port() == this->connection_context.origin_server_port)
		{
			this->connection_context.reconnect_on_error = true;
			this->on_connect();
		}
		else
		{
			this->connection_context.origin_server_name = this->_request_parser._header.host();
			this->connection_context.origin_server_port = this->_request_parser._header.port();
			asio::ip::tcp::resolver::query query(this->_request_parser._header.host(), std::to_string(this->_request_parser._header.port()));
			auto self(this->shared_from_this());
			this->connection_context.connection_state = proxy_connection_state::resolve_origin_server_address;
			this->set_timer();
			logger->info("{} connect to {}:{}", logger_prefix, this->_request_parser._header.host(), this->_request_parser._header.port());
			this->resolver.async_resolve(query,
										 this->strand.wrap([this, self](const error_code& error, asio::ip::tcp::resolver::iterator iterator)
			{
				if (this->cancel_timer())
				{
					if (!error)
					{
						this->on_resolved(iterator);
					}
					else
					{
						this->on_error(error);
					}
				}
			})
										 );
		}
	}

	void http_proxy_server_connection::async_write_data_to_origin_server(const char* write_buffer, std::size_t offset, std::size_t size)
	{
		auto self(this->shared_from_this());
		this->set_timer();
		this->origin_server_socket.async_write_some(asio::buffer(write_buffer + offset, size),
													this->strand.wrap([this, self, write_buffer, offset, size](const error_code& error, std::size_t bytes_transferred)
		{
			if (this->cancel_timer())
			{
				if (!error)
				{
					this->connection_context.reconnect_on_error = false;
					if (bytes_transferred < size)
					{
						this->async_write_data_to_origin_server(write_buffer, offset + bytes_transferred, size - bytes_transferred);
					}
					else
					{
						this->on_origin_server_data_written();
					}
				}
				else
				{
					this->on_error(error);
				}
			}
		})
													);
	}

	void http_proxy_server_connection::async_write_data_to_proxy_client(const char* write_buffer, std::size_t offset, std::size_t size)
	{
		auto self(this->shared_from_this());
		this->set_timer();
		this->proxy_client_socket.async_write_some(asio::buffer(write_buffer + offset, size),
												   this->strand.wrap([this, self, write_buffer, offset, size](const error_code& error, std::size_t bytes_transferred)
		{
			if (this->cancel_timer())
			{
				if (!error)
				{
					if (bytes_transferred < size)
					{
						this->async_write_data_to_proxy_client(write_buffer, offset + bytes_transferred, size - bytes_transferred);
					}
					else
					{
						this->on_proxy_client_data_written();
					}
				}
				else
				{
					this->on_error(error);
				}
			}
		})
												   );
	}

	void http_proxy_server_connection::start_tunnel_transfer()
	{
		this->connection_context.connection_state = proxy_connection_state::tunnel_transfer;
		this->async_read_data_from_proxy_client();
		this->async_read_data_from_origin_server(false);
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
		this->modified_response_data += "Server: AzureHttpProxy\r\n";
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
		response_content += "azure http proxy server";
		response_content += "</center></body></html>";
		this->modified_response_data += std::to_string(response_content.size());
		this->modified_response_data += "\r\n";
		this->modified_response_data += "Proxy-Connection: close\r\n";
		this->modified_response_data += "\r\n";
		if (_request_parser._header.method() != "HEAD")
		{
			this->modified_response_data += response_content;
		}
		this->encryptor->transform(reinterpret_cast<unsigned char*>(&modified_response_data[0]), modified_response_data.size(), 16);
		this->connection_context.connection_state = proxy_connection_state::report_error;
		auto self(this->shared_from_this());
		this->async_write_data_to_proxy_client(this->modified_response_data.data(), 0, this->modified_response_data.size());
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
		content += "<body bgcolor=\"white\"><center><h1>407 Proxy Authentication Required</h1></center><hr><center>azure http proxy server</center></body></html>";
		this->modified_response_data = "HTTP/1.1 407 Proxy Authentication Required\r\n";
		this->modified_response_data += "Server: AzureHttpProxy\r\n";
		this->modified_response_data += "Proxy-Authenticate: Basic realm=\"AzureHttpProxy\"\r\n";
		this->modified_response_data += "Content-Type: text/html\r\n";
		this->modified_response_data += "Connection: Close\r\n";
		this->modified_response_data += "Content-Length: ";
		this->modified_response_data += std::to_string(content.size());
		this->modified_response_data += "\r\n\r\n";
		this->modified_response_data += content;
		this->encryptor->transform(reinterpret_cast<unsigned char*>(&modified_response_data[0]), modified_response_data.size(), 16);
		this->connection_context.connection_state = proxy_connection_state::report_error;
		this->async_write_data_to_proxy_client(this->modified_response_data.data(), 0, this->modified_response_data.size());
	}

	void http_proxy_server_connection::set_timer()
	{
		if (this->timer.expires_from_now(std::chrono::seconds(http_proxy_server_config::get_instance().get_timeout())) != 0)
		{
			assert(false);
		}
		auto self(this->shared_from_this());
		this->timer.async_wait(this->strand.wrap([this, self](const error_code& error)
		{
			if (error != asio::error::operation_aborted)
			{
				this->on_timeout();
			}
		}));
	}

	bool http_proxy_server_connection::cancel_timer()
	{
		std::size_t ret = this->timer.cancel();
		assert(ret <= 1);
		return ret == 1;
	}

	void http_proxy_server_connection::on_resolved(asio::ip::tcp::resolver::iterator endpoint_iterator)
	{
		if (this->origin_server_socket.is_open())
		{
			for (auto iter = endpoint_iterator; iter != asio::ip::tcp::resolver::iterator(); ++iter)
			{
				if (*(this->connection_context.origin_server_endpoint) == iter->endpoint())
				{
					this->connection_context.reconnect_on_error = true;
					this->on_connect();
					return;
				}
				error_code ec;
				this->origin_server_socket.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
				this->origin_server_socket.close(ec);
			}
		}
		this->connection_context.origin_server_endpoint = std::make_unique<asio::ip::tcp::endpoint>(endpoint_iterator->endpoint());
		auto self(this->shared_from_this());
		this->connection_context.connection_state = proxy_connection_state::connect_to_origin_server;
		this->set_timer();
		this->origin_server_socket.async_connect(endpoint_iterator->endpoint(),
												 this->strand.wrap([this, self, endpoint_iterator](const error_code& error) mutable
		{
			if (this->cancel_timer())
			{
				if (!error)
				{
					this->on_connect();
				}
				else
				{
					error_code ec;
					this->origin_server_socket.close(ec);
					if (++endpoint_iterator != asio::ip::tcp::resolver::iterator())
					{
						this->on_resolved(endpoint_iterator);
					}
					else
					{
						this->on_error(error);
					}
				}
			}
		})
												 );
	}

	void http_proxy_server_connection::on_connect()
	{
		logger->info("{} connect to server {} suc", logger_prefix, _request_parser._header.host());
		if (_request_parser._header.method() == "CONNECT")
		{
			const unsigned char response_message[] = "HTTP/1.1 200 Connection Established\r\nConnection: Close\r\n\r\n";
			this->modified_response_data.resize(sizeof(response_message) - 1);
			this->encryptor->encrypt(response_message, reinterpret_cast<unsigned char*>(&this->modified_response_data[0]), this->modified_response_data.size());
			this->connection_context.connection_state = proxy_connection_state::report_connection_established;
			this->async_write_data_to_proxy_client(&this->modified_response_data[0], 0, this->modified_response_data.size());
		}
		else
		{
			logger->info("{} send request to origin server method {} resource {} header_counter {}", logger_prefix, this->_request_parser._header.method(), this->_request_parser._header.path_and_query(), this->_request_parser._header.get_header_counter());
			this->connection_context.connection_state = proxy_connection_state::write_http_request_header;
			this->async_write_data_to_origin_server(reinterpret_cast<const char*>(upgoing_buffer_write.data()), 0, read_request_context.send_buffer_size);
		}
	}

	void http_proxy_server_connection::on_proxy_client_data_arrived(std::size_t bytes_transferred)
	{
		logger->trace("{} on_proxy_client_data_arrived size {}", logger_prefix, bytes_transferred);
		if (this->connection_context.connection_state == proxy_connection_state::read_cipher_data)
		{
			std::copy(this->upgoing_buffer_read.begin(), this->upgoing_buffer_read.begin() + bytes_transferred, std::back_inserter(this->encrypted_cipher_info));
			bool set_result = try_set_security_info();
			if (!set_result)
			{
				logger->warn("{} invalid security info connection fail", logger_prefix);

			}
			logger->info("{} security info set begin to chat", logger_prefix);
			return;
		}
		assert(this->encryptor != nullptr && this->decryptor != nullptr);
		this->decryptor->decrypt(upgoing_buffer_read.data(), upgoing_buffer_write.data(), bytes_transferred);
		if (this->connection_context.connection_state == proxy_connection_state::tunnel_transfer)
		{
			this->async_write_data_to_origin_server(reinterpret_cast<const char*>(upgoing_buffer_write.data()), 0, bytes_transferred);
			return;
		}
		if (!_request_parser.append_input(upgoing_buffer_write.data(), bytes_transferred))
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
				std::copy(header_data.begin(), header_data.end(), upgoing_buffer_write.data() + send_buffer_size);
				send_buffer_size += header_data.size();
				this->read_request_context.is_proxy_client_keep_alive = _request_parser._header.is_keep_alive();
			}
			else if (cur_parse_result.first == http_parser_result::read_some_content)
			{
				std::copy(cur_parse_result.second.begin(), cur_parse_result.second.end(), upgoing_buffer_write.data() + send_buffer_size);
				send_buffer_size += cur_parse_result.second.size();
			}
			else if (cur_parse_result.first == http_parser_result::read_content_end)
			{
				std::copy(cur_parse_result.second.begin(), cur_parse_result.second.end(), upgoing_buffer_write.data() + send_buffer_size);
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
					async_connect_to_origin_server();
					return;
				}
				else
				{
					read_request_context.send_buffer_size = send_buffer_size;
					async_connect_to_origin_server();
					return;
				}
			}
			else
			{
				async_write_data_to_origin_server(reinterpret_cast<const char *>(upgoing_buffer_write.data()), 0, send_buffer_size);
			}
		}
		else
		{
			async_read_data_from_proxy_client();
		}
		
	}

	void http_proxy_server_connection::on_origin_server_data_arrived(std::size_t bytes_transferred)
	{
		logger->trace("{} on_origin_server_data_arrived size {}", logger_prefix, bytes_transferred);
		if (this->connection_context.connection_state == proxy_connection_state::tunnel_transfer)
		{
			this->encryptor->encrypt(downgoing_buffer_read.data(), downgoing_buffer_write.data(), bytes_transferred);
			this->async_write_data_to_proxy_client(reinterpret_cast<const char*>(downgoing_buffer_write.data()), 0, bytes_transferred);
			return;
		}
		if (!_response_parser.append_input(downgoing_buffer_read.data(), bytes_transferred))
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
				std::copy(header_data.begin(), header_data.end(), downgoing_buffer_write.data() + send_buffer_size);
				send_buffer_size += header_data.size();
				this->connection_context.connection_state = proxy_connection_state::write_http_response_header;
			}
			else if (cur_parse_result.first == http_parser_result::read_some_content)
			{
				this->connection_context.connection_state = proxy_connection_state::write_http_response_content;
				std::copy(cur_parse_result.second.begin(), cur_parse_result.second.end(), downgoing_buffer_write.data() + send_buffer_size);
				send_buffer_size += cur_parse_result.second.size();

			}
			else if(cur_parse_result.first == http_parser_result::read_content_end)
			{
				this->connection_context.connection_state = proxy_connection_state::write_http_response_content;
				_response_parser.reset_header();
				std::copy(cur_parse_result.second.begin(), cur_parse_result.second.end(), downgoing_buffer_write.data() + send_buffer_size);
				send_buffer_size += cur_parse_result.second.size();
			}
			else
			{
				break;
			}
		}
		if (send_buffer_size)
		{
			this->encryptor->encrypt(downgoing_buffer_read.data(), downgoing_buffer_write.data(), send_buffer_size);
			this->async_write_data_to_proxy_client(reinterpret_cast<const char*>(this->downgoing_buffer_write.data()), 0, send_buffer_size);
		}
		else
		{
			async_read_data_from_origin_server();
		}
		
	}

	void http_proxy_server_connection::on_proxy_client_data_written()
	{
		if (this->connection_context.connection_state == proxy_connection_state::tunnel_transfer)
		{
			this->async_read_data_from_origin_server();
		}
		else if (this->connection_context.connection_state == proxy_connection_state::write_http_response_header
				 || this->connection_context.connection_state == proxy_connection_state::write_http_response_content)
		{
			if (_response_parser.status() == http_parser_status::read_header)
			{
				error_code ec;
				if (!this->read_response_context.is_origin_server_keep_alive)
				{
					this->origin_server_socket.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
					this->origin_server_socket.close(ec);
				}
				if (this->read_request_context.is_proxy_client_keep_alive)
				{
					this->connection_context.connection_state = proxy_connection_state::read_http_request_header;
					this->async_read_data_from_proxy_client();
				}
				else
				{
					this->proxy_client_socket.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
					this->proxy_client_socket.close(ec);
				}
			}
			else
			{
				this->connection_context.connection_state = proxy_connection_state::read_http_response_content;
				this->async_read_data_from_origin_server();
			}
		}
		else if (this->connection_context.connection_state == proxy_connection_state::report_connection_established)
		{
			this->start_tunnel_transfer();
		}
		else if (this->connection_context.connection_state == proxy_connection_state::report_error)
		{
			error_code ec;
			if (this->origin_server_socket.is_open())
			{
				this->origin_server_socket.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
				this->origin_server_socket.close(ec);
			}
			if (this->proxy_client_socket.is_open())
			{
				this->proxy_client_socket.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
				this->proxy_client_socket.close(ec);
			}
		}
	}

	void http_proxy_server_connection::on_origin_server_data_written()
	{
		if (this->connection_context.connection_state == proxy_connection_state::tunnel_transfer)
		{
			this->async_read_data_from_proxy_client();
		}
		else if (this->connection_context.connection_state == proxy_connection_state::write_http_request_header
				 || this->connection_context.connection_state == proxy_connection_state::write_http_request_content)
		{
			if (_request_parser.status() == http_parser_status::read_header)
			{
				this->connection_context.connection_state = proxy_connection_state::read_http_response_header;
				this->async_read_data_from_origin_server();
			}
			else
			{
				this->connection_context.connection_state = proxy_connection_state::read_http_request_content;
				this->async_read_data_from_proxy_client();
			}
		}
	}

	void http_proxy_server_connection::on_error(const error_code& error)
	{
		if (this->connection_context.connection_state == proxy_connection_state::resolve_origin_server_address)
		{
			this->report_error("504", "Gateway Timeout", "Failed to resolve the hostname");
		}
		else if (this->connection_context.connection_state == proxy_connection_state::connect_to_origin_server)
		{
			this->report_error("502", "Bad Gateway", "Failed to connect to origin server");
		}
		else if (this->connection_context.connection_state == proxy_connection_state::write_http_request_header && this->connection_context.reconnect_on_error)
		{
			logger->warn("{} reconnect to origin server by error", logger_prefix);
			error_code ec;
			this->origin_server_socket.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
			this->origin_server_socket.close(ec);
			this->async_connect_to_origin_server();
		}
		else
		{
			logger->warn("{} shutdown connections by error", logger_prefix);
			error_code ec;
			if (this->origin_server_socket.is_open())
			{
				this->origin_server_socket.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
				this->origin_server_socket.close(ec);
			}
			if (this->proxy_client_socket.is_open())
			{
				this->proxy_client_socket.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
				this->proxy_client_socket.close(ec);
			}
		}
	}

	void http_proxy_server_connection::on_timeout()
	{
		logger->warn("{} connection timeout", logger_prefix);
		error_code ec;
		if (this->origin_server_socket.is_open())
		{
			this->origin_server_socket.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
			this->origin_server_socket.close(ec);
		}
		if (this->proxy_client_socket.is_open())
		{
			this->proxy_client_socket.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
			this->proxy_client_socket.close(ec);
		}
	}
	bool http_proxy_server_connection::try_set_security_info()
	{

		if (this->encrypted_cipher_info.size() < this->rsa_pri.modulus_size())
		{
			this->async_read_data_from_proxy_client(1, std::min(static_cast<std::size_t>(this->rsa_pri.modulus_size()) - this->encrypted_cipher_info.size(), BUFFER_LENGTH));
			return true;
		}
		assert(this->encrypted_cipher_info.size() == this->rsa_pri.modulus_size());
		std::vector<unsigned char> decrypted_cipher_info(this->rsa_pri.modulus_size());

		if (86 != this->rsa_pri.decrypt(this->rsa_pri.modulus_size(), this->encrypted_cipher_info.data(), decrypted_cipher_info.data(), rsa_padding::pkcs1_oaep_padding))
		{
			return false;
		}

		if (decrypted_cipher_info[0] != 'A' ||
			decrypted_cipher_info[1] != 'H' ||
			decrypted_cipher_info[2] != 'P' ||
			decrypted_cipher_info[3] != 0 ||
			decrypted_cipher_info[4] != 0 ||
			decrypted_cipher_info[6] != 0
			)
		{
			return false;
		}

		// 5 cipher code

		// 0x00 aes-128-cfb
		// 0x01 aes-128-cfb8
		// 0x02 aes-128-cfb1
		// 0x03 aes-128-ofb
		// 0x04 aes-128-ctr
		// 0x05 aes-192-cfb
		// 0x06 aes-192-cfb8
		// 0x07 aes-192-cfb1
		// 0x08 aes-192-ofb
		// 0x09 aes-192-ctr
		// 0x0A aes-256-cfb
		// 0x0B aes-256-cfb8
		// 0x0C aes-256-cfb1
		// 0x0D aes-256-ofb
		// 0x0E aes-256-ctr
		char cipher_code = decrypted_cipher_info[5];
		if (cipher_code == '\x00' || cipher_code == '\x05' || cipher_code == '\x0A')
		{
			// aes-xxx-cfb
			std::size_t ivec_size = 16;
			std::size_t key_bits = 256; // aes-256-cfb
			if (cipher_code == '\x00')
			{
				// aes-128-cfb
				key_bits = 128;
			}
			else if (cipher_code == '\x05')
			{
				// aes-192-cfb
				key_bits = 192;
			}
			this->encryptor = std::unique_ptr<stream_encryptor>(new aes_cfb128_encryptor(&decrypted_cipher_info[23], key_bits, &decrypted_cipher_info[7]));
			this->decryptor = std::unique_ptr<stream_decryptor>(new aes_cfb128_decryptor(&decrypted_cipher_info[23], key_bits, &decrypted_cipher_info[7]));
		}
		else if (cipher_code == '\x01' || cipher_code == '\x06' || cipher_code == '\x0B')
		{
			// ase-xxx-cfb8
			std::size_t ivec_size = 16;
			std::size_t key_bits = 256; // aes-256-cfb8
			if (cipher_code == '\x01')
			{
				// aes-128-cfb8
				key_bits = 128;
			}
			else if (cipher_code == '\x06')
			{
				// aes-192-cfb8
				key_bits = 192;
			}
			this->encryptor = std::unique_ptr<stream_encryptor>(new aes_cfb8_encryptor(&decrypted_cipher_info[23], key_bits, &decrypted_cipher_info[7]));
			this->decryptor = std::unique_ptr<stream_decryptor>(new aes_cfb8_decryptor(&decrypted_cipher_info[23], key_bits, &decrypted_cipher_info[7]));
		}
		else if (cipher_code == '\x02' || cipher_code == '\x07' || cipher_code == '\x0C')
		{
			// ase-xxx-cfb1
			std::size_t ivec_size = 16;
			std::size_t key_bits = 256; // aes-256-cfb1
			if (cipher_code == '\x02')
			{
				// aes-128-cfb1
				key_bits = 128;
			}
			else if (cipher_code == '\x07')
			{
				// aes-192-cfb1
				key_bits = 192;
			}
			this->encryptor = std::unique_ptr<stream_encryptor>(new aes_cfb1_encryptor(&decrypted_cipher_info[23], key_bits, &decrypted_cipher_info[7]));
			this->decryptor = std::unique_ptr<stream_decryptor>(new aes_cfb1_decryptor(&decrypted_cipher_info[23], key_bits, &decrypted_cipher_info[7]));
		}
		else if (cipher_code == '\x03' || cipher_code == '\x08' || cipher_code == '\x0D')
		{
			// ase-xxx-ofb
			std::size_t ivec_size = 16;
			std::size_t key_bits = 256; // aes-256-ofb
			if (cipher_code == '\x03')
			{
				// aes-128-ofb
				key_bits = 128;
			}
			else if (cipher_code == '\x08')
			{
				// aes-192-ofb
				key_bits = 192;
			}
			this->encryptor = std::unique_ptr<stream_encryptor>(new aes_ofb128_encryptor(&decrypted_cipher_info[23], key_bits, &decrypted_cipher_info[7]));
			this->decryptor = std::unique_ptr<stream_decryptor>(new aes_ofb128_decryptor(&decrypted_cipher_info[23], key_bits, &decrypted_cipher_info[7]));
		}
		// else if (cipher_code == '\x04' || cipher_code == '\x09' || cipher_code == '\x0E')
		// {
		// 	// ase-xxx-ctr
		// 	std::size_t ivec_size = 16;
		// 	std::size_t key_bits = 256; // aes-256-ctr
		// 	if (cipher_code == '\x04')
		// 	{
		// 		// aes-128-ctr
		// 		key_bits = 128;
		// 	}
		// 	else if (cipher_code == '\x09')
		// 	{
		// 		// aes-192-ctr
		// 		key_bits = 192;
		// 	}
		// 	std::vector<char> ivec(ivec_size, 0);
		// 	this->encryptor = std::unique_ptr<stream_encryptor>(new aes_ctr128_encryptor(&decrypted_cipher_info[23], key_bits, ivec.data()));
		// 	this->decryptor = std::unique_ptr<stream_decryptor>(new aes_ctr128_decryptor(&decrypted_cipher_info[23], key_bits, ivec.data()));
		// }
		if (this->encryptor == nullptr || this->decryptor == nullptr)
		{
			return false;
		}
		this->connection_context.connection_state = proxy_connection_state::read_http_request_header;
		this->async_read_data_from_proxy_client();
		return true;
	}

} // namespace azure_proxy

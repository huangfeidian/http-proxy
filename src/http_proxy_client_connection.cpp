/*
 *    http_proxy_client_connection.cpp:
 *
 *    Copyright (C) 2013-2015 limhiaoing <blog.poxiao.me> All Rights Reserved.
 *
 */

#include <algorithm>
#include <cstring>
#include <utility>

#include "http_proxy_client_config.hpp"
#include "http_proxy_client_connection.hpp"
#include "http_proxy_client_stat.hpp"
#include "key_generator.hpp"


namespace azure_proxy
{

	http_proxy_client_connection::http_proxy_client_connection(asio::ip::tcp::socket&& ua_socket, std::shared_ptr<spdlog::logger> in_logger, std::uint32_t in_connection_count) :
		strand(ua_socket.get_io_service()),
		user_agent_socket(std::move(ua_socket)),
		proxy_server_socket(this->user_agent_socket.get_io_service()),
		resolver(this->user_agent_socket.get_io_service()),
		connection_state(proxy_connection_state::ready),
		timer(this->user_agent_socket.get_io_service()),
		timeout(std::chrono::seconds(http_proxy_client_config::get_instance().get_timeout())),
		logger(in_logger),
		connection_count(in_connection_count),
		logger_prefix("connection " +std::to_string(connection_count) + ": ")
	{

		http_proxy_client_stat::get_instance().increase_current_connections();
		logger->info("{} new connection come! total connection count {}", logger_prefix, http_proxy_client_stat::get_instance().get_current_connections());
	}

	http_proxy_client_connection::~http_proxy_client_connection()
	{
		http_proxy_client_stat::get_instance().decrease_current_connections();
	}

	std::shared_ptr<http_proxy_client_connection> http_proxy_client_connection::create(asio::ip::tcp::socket&& ua_socket, std::shared_ptr<spdlog::logger> in_logger, std::uint32_t in_connection_count)
	{
		return std::shared_ptr<http_proxy_client_connection>(new http_proxy_client_connection(std::move(ua_socket), in_logger, in_connection_count));
	}

	void http_proxy_client_connection::start()
	{
		std::array<unsigned char, 86> cipher_info_raw;
		cipher_info_raw.fill(0);
		// 0 ~ 2
		cipher_info_raw[0] = 'A';
		cipher_info_raw[1] = 'H';
		cipher_info_raw[2] = 'P';

		// 3 zero
		// 4 zero

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

		char cipher_code = 0;
		const auto& cipher_name = http_proxy_client_config::get_instance().get_cipher();
		if (cipher_name.size() > 7 && std::equal(cipher_name.begin(), cipher_name.begin() + 3, "aes"))
		{
			// aes
			std::vector<unsigned char> ivec(16);
			std::vector<unsigned char> key_vec;
			aes_generator::generate(cipher_name, cipher_code, ivec, key_vec, this->encryptor, this->decryptor);
			std::copy(ivec.cbegin(), ivec.cend(), cipher_info_raw.begin() + 7);
			std::copy(key_vec.cbegin(), key_vec.cend(), cipher_info_raw.begin() + 23);
		}

		if (!this->encryptor || !this->decryptor)
		{
			return;
		}

		// 5 cipher code
		cipher_info_raw[5] = static_cast<unsigned char>(cipher_code);

		// 6 zero

		rsa rsa_pub(http_proxy_client_config::get_instance().get_rsa_public_key());
		if (rsa_pub.modulus_size() < 128)
		{
			return;
		}

		this->encrypted_cipher_info.resize(rsa_pub.modulus_size());
		if (this->encrypted_cipher_info.size() != rsa_pub.encrypt(cipher_info_raw.size(), cipher_info_raw.data(), this->encrypted_cipher_info.data(), rsa_padding::pkcs1_oaep_padding))
		{
			return;
		}

		auto self(this->shared_from_this());
		asio::ip::tcp::resolver::query query(http_proxy_client_config::get_instance().get_proxy_server_address(), std::to_string(http_proxy_client_config::get_instance().get_proxy_server_port()));
		this->connection_state = proxy_connection_state::resolve_proxy_server_address;
		this->set_timer();
		this->resolver.async_resolve(query, [this, self](const error_code& error, asio::ip::tcp::resolver::iterator iterator)
		{
			if (this->cancel_timer())
			{
				if (!error)
				{
					this->connection_state = proxy_connection_state::connecte_to_proxy_server;
					this->set_timer();
					this->proxy_server_socket.async_connect(*iterator, this->strand.wrap([this, self](const error_code& error)
					{
						if (this->cancel_timer())
						{
							if (!error)
							{
								this->on_connection_established();
							}
							else
							{
								this->on_error(error);
							}
						}
					}));
				}
				else
				{
					this->on_error(error);
				}
			}
		});
	}

	void http_proxy_client_connection::async_read_data_from_user_agent(std::size_t at_least_size, std::size_t at_most_size)
	{
		logger->debug("{} async_read_data_from_user_agent begin", logger_prefix);
		auto self(this->shared_from_this());
		this->set_timer();
		if (this->logger->level() == spdlog::level::level_enum::off)
		{
			this->user_agent_socket.async_read_some(asio::buffer(this->upgoing_buffer_read.data(), this->upgoing_buffer_read.size()), this->strand.wrap([this, self](const error_code& error, std::size_t bytes_transferred)
			{
				if (this->cancel_timer())
				{
					if (!error)
					{
						http_proxy_client_stat::get_instance().on_upgoing_recv(static_cast<std::uint32_t>(bytes_transferred));
						this->decryptor->decrypt(reinterpret_cast<const unsigned char*>(&this->upgoing_buffer_read[0]), reinterpret_cast<unsigned char*>(&this->upgoing_buffer_write[0]), bytes_transferred);
						this->async_write_data_to_proxy_server(this->upgoing_buffer_write.data(), 0, bytes_transferred);

					}
					else
					{
						this->on_error(error);
					}
				}
			}));
		}
		else
		{
			asio::async_read(this->user_agent_socket,
				asio::buffer(&this->upgoing_buffer_read[0], at_most_size),
				asio::transfer_at_least(at_least_size),
				this->strand.wrap([this, self](const error_code& error, std::size_t bytes_transferred)
			{
				if (this->cancel_timer())
				{
					if (!error)
					{
						this->on_user_agent_data_arrived(bytes_transferred);
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

	void http_proxy_client_connection::async_read_data_from_proxy_server(bool set_timer, std::size_t at_least_size, std::size_t at_most_size)
	{
		logger->debug("{} async_read_data_from_proxy_server begin", logger_prefix);
		auto self(this->shared_from_this());
		if (set_timer)
		{
			this->set_timer();
		}
		if (logger->level() == spdlog::level::off)
		{
			this->proxy_server_socket.async_read_some(asio::buffer(this->downgoing_buffer_read.data(), this->downgoing_buffer_read.size()), this->strand.wrap([this, self](const error_code& error, std::size_t bytes_transferred)
			{
				if (this->cancel_timer())
				{
					if (!error)
					{
						http_proxy_client_stat::get_instance().on_downgoing_recv(static_cast<std::uint32_t>(bytes_transferred));
						this->decryptor->decrypt(reinterpret_cast<const unsigned char*>(&this->downgoing_buffer_read[0]), reinterpret_cast<unsigned char*>(&this->downgoing_buffer_write[0]), bytes_transferred);

						this->async_write_data_to_user_agent(this->downgoing_buffer_write.data(), 0, bytes_transferred);

					}
					else
					{
						this->on_error(error);
					}
				}
			}));
		}
		else
		{
			asio::async_read(this->proxy_server_socket,
				asio::buffer(&this->downgoing_buffer_read[0], at_most_size),
				asio::transfer_at_least(at_least_size),
				this->strand.wrap([this, self](const error_code& error, std::size_t bytes_transferred)
			{
				if (this->cancel_timer())
				{
					if (!error)
					{
						http_proxy_client_stat::get_instance().on_downgoing_recv(static_cast<std::uint32_t>(bytes_transferred));
						this->decryptor->decrypt(reinterpret_cast<const unsigned char*>(&this->downgoing_buffer_read[0]), reinterpret_cast<unsigned char*>(&this->downgoing_buffer_write[0]), bytes_transferred);
						this->on_proxy_server_data_arrived(bytes_transferred);
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

	void http_proxy_client_connection::async_write_data_to_user_agent(const char* write_buffer, std::size_t offset, std::size_t size)
	{
		auto self(this->shared_from_this());
		this->set_timer();
		this->user_agent_socket.async_write_some(asio::buffer(write_buffer + offset, size),
			this->strand.wrap([this, self, write_buffer, offset, size](const error_code& error, std::size_t bytes_transferred)
		{
			if (this->cancel_timer())
			{
				if (!error)
				{
					http_proxy_client_stat::get_instance().on_downgoing_send(static_cast<std::uint32_t>(bytes_transferred));
					if (bytes_transferred < size)
					{
						this->async_write_data_to_user_agent(write_buffer, offset + bytes_transferred, size - bytes_transferred);
					}
					else
					{
						this->async_read_data_from_proxy_server();
					}
				}
				else
				{
					this->on_error(error);
				}
			}
		}));
	}

	void http_proxy_client_connection::async_write_data_to_proxy_server(const char* write_buffer, std::size_t offset, std::size_t size)
	{
		auto self(this->shared_from_this());
		this->set_timer();
		this->proxy_server_socket.async_write_some(asio::buffer(write_buffer + offset, size),
			this->strand.wrap([this, self, write_buffer, offset, size](const error_code& error, std::size_t bytes_transferred)
		{
			if (this->cancel_timer())
			{
				if (!error)
				{
					http_proxy_client_stat::get_instance().on_upgoing_send(static_cast<std::uint32_t>(bytes_transferred));
					if (bytes_transferred < size)
					{
						this->async_write_data_to_proxy_server(write_buffer, offset + bytes_transferred, size - bytes_transferred);
					}
					else
					{
						this->async_read_data_from_user_agent();
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

	void http_proxy_client_connection::set_timer()
	{
		if (this->timer.expires_from_now(this->timeout) != 0)
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

	bool http_proxy_client_connection::cancel_timer()
	{
		std::size_t ret = this->timer.cancel();
		assert(ret <= 1);
		return ret == 1;
	}

	void http_proxy_client_connection::on_connection_established()
	{
		logger->info("{} connected to proxy server established", logger_prefix);
		this->async_write_data_to_proxy_server(reinterpret_cast<const char*>(this->encrypted_cipher_info.data()), 0, this->encrypted_cipher_info.size());
		logger->info("{} send cipher to server size {}", logger_prefix, this->encrypted_cipher_info.size());
		this->async_read_data_from_proxy_server(false);
	}

	void http_proxy_client_connection::on_error(const error_code& error)
	{
		logger->warn("{} error shutdown connection {}", logger_prefix, error.message());
		this->cancel_timer();
		error_code ec;
		if (this->proxy_server_socket.is_open())
		{
			this->proxy_server_socket.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
			this->proxy_server_socket.close(ec);
		}
		if (this->user_agent_socket.is_open())
		{
			this->user_agent_socket.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
			this->user_agent_socket.close(ec);
		}
	}

	void http_proxy_client_connection::on_timeout()
	{
		
		if (this->connection_state == proxy_connection_state::resolve_proxy_server_address)
		{
			this->resolver.cancel();
		}
		else
		{
			logger->warn("{} on_timeout shutdown connection", logger_prefix);
			error_code ec;
			if (this->proxy_server_socket.is_open())
			{
				this->proxy_server_socket.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
				this->proxy_server_socket.close(ec);
			}
			if (this->user_agent_socket.is_open())
			{
				this->user_agent_socket.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
				this->user_agent_socket.close(ec);
			}
		}
	}
	void http_proxy_client_connection::on_proxy_server_data_arrived(std::size_t bytes_transferred)
	{
		logger->debug("{} on_proxy_server_data_arrived bytes {}", logger_prefix, bytes_transferred);
		if (connection_state == proxy_connection_state::tunnel_transfer)
		{
			decryptor->decrypt(reinterpret_cast<const unsigned char*>(downgoing_buffer_read.data()), reinterpret_cast<unsigned char*>(downgoing_buffer_write.data()), bytes_transferred);
			this->async_write_data_to_user_agent(this->downgoing_buffer_write.data(), 0, bytes_transferred);
			return;
		}
		if (!_http_response_parser.append_input(reinterpret_cast<const unsigned char*>(downgoing_buffer_write.data()), bytes_transferred))
		{
			report_error("400", "Bad request", "buffer overflow");
			return;
		}
		std::uint32_t send_buffer_size = 0;
		while (true)
		{
			auto cur_parse_result = _http_response_parser.parse();
			if (cur_parse_result.first >= http_parser_result::parse_error)
			{
				report_error(cur_parse_result.first);
				return;
			}
			else if (cur_parse_result.first == http_parser_result::read_one_header)
			{
				auto cur_header_counter = _http_response_parser._header.get_header_value("header_counter");
				if (cur_header_counter)
				{
					logger->info("request {0} back", cur_header_counter.value());
				}
				_http_response_parser._header.erase_header("header_counter");
				if (_http_request_parser._header.method() == "CONNECT" && _http_response_parser._header.status_code() == 200)
				{
					connection_state = proxy_connection_state::tunnel_transfer;
				}
				auto header_data = _http_response_parser._header.encode_to_data();
				//logger->trace("{} read proxy response header data {}", logger_prefix, header_data);
				_http_request_parser.reset_header();
				
				std::copy(header_data.begin(), header_data.end(), downgoing_buffer_write.data() + send_buffer_size);
				send_buffer_size += header_data.size();
			}
			else if (cur_parse_result.first == http_parser_result::read_some_content)
			{
				std::copy(cur_parse_result.second.begin(), cur_parse_result.second.end(), downgoing_buffer_write.data() + send_buffer_size);
				send_buffer_size += cur_parse_result.second.size();
			}
			else if(cur_parse_result.first == http_parser_result::read_content_end)
			{
				_http_response_parser.reset_header();
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
			this->async_write_data_to_user_agent(this->downgoing_buffer_write.data(), 0, send_buffer_size);
		}
		else
		{
			async_read_data_from_proxy_server();
		}
		
	}
	void http_proxy_client_connection::on_user_agent_data_arrived(std::size_t bytes_transferred)
	{
		logger->debug("{} on_user_agent_data_arrived size {}", logger_prefix, bytes_transferred);
		//logger->trace("{} data is {}", logger_prefix, std::string(upgoing_buffer_read.data(), upgoing_buffer_read.data() + bytes_transferred));
		static std::atomic<uint32_t> header_counter = 0;
		if (connection_state == proxy_connection_state::tunnel_transfer)
		{
			encryptor->encrypt(reinterpret_cast<const unsigned char*>(upgoing_buffer_read.data()), reinterpret_cast<unsigned char*>(upgoing_buffer_write.data()), bytes_transferred);
			async_write_data_to_proxy_server(upgoing_buffer_write.data(), 0, bytes_transferred);
			return;

		}
		if (!_http_request_parser.append_input(reinterpret_cast<const unsigned char*>(&upgoing_buffer_read[0]), bytes_transferred))
		{
			report_error("400", "Bad request", "buffer overflow");
			return;
		}
		std::uint32_t send_buffer_size = 0;
		while (true)
		{
			auto cur_parse_result = _http_request_parser.parse();
			//logger->trace("{} after one parse status is {}", logger_prefix, _http_request_parser.status());
			if (cur_parse_result.first >= http_parser_result::parse_error)
			{
				report_error(cur_parse_result.first);
				return;
			}
			else if (cur_parse_result.first == http_parser_result::read_one_header)
			{
				_http_request_parser._header.set_header_counter(std::to_string(header_counter++));
				auto header_data = _http_request_parser._header.encode_to_data();
				//logger->trace("{} read ua request header data {}", logger_prefix, header_data);
				std::copy(header_data.begin(), header_data.end(), upgoing_buffer_write.data() + send_buffer_size);
				send_buffer_size += header_data.size();
			}
			else if (cur_parse_result.first == http_parser_result::read_some_content)
			{
				std::copy(cur_parse_result.second.begin(), cur_parse_result.second.end(), upgoing_buffer_write.data() + send_buffer_size);
				send_buffer_size += cur_parse_result.second.size();
			}
			else if(cur_parse_result.first == http_parser_result::read_content_end)
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
			encryptor->transform(reinterpret_cast<unsigned char*>(upgoing_buffer_write.data()), send_buffer_size, 256);
			this->async_write_data_to_proxy_server(this->upgoing_buffer_write.data(), 0, send_buffer_size);
		}
		else
		{
			async_read_data_from_user_agent();
		}
		
	}
	void http_proxy_client_connection::report_error(const std::string& status_code, const std::string& status_description, const std::string& error_message)
	{
		logger->warn("{} report error status_code {} status_description {} error_message {}", logger_prefix, status_code, status_description, error_message);
		error_code ec;
		if (this->proxy_server_socket.is_open())
		{
			this->proxy_server_socket.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
			this->proxy_server_socket.close(ec);
		}
		if (this->user_agent_socket.is_open())
		{
			this->user_agent_socket.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
			this->user_agent_socket.close(ec);
		}
	}
	void http_proxy_client_connection::report_error(http_parser_result _status)
	{
		auto error_detail = from_praser_result_to_description(_status);
		report_error(std::to_string(std::get<0>(error_detail)), std::get<1>(error_detail), std::get<2>(error_detail));
	}
} // namespace azure_proxy

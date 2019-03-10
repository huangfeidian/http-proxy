#include "http_proxy_connection.hpp"

namespace azure_proxy
{
	http_proxy_connection::http_proxy_connection(asio::ip::tcp::socket&& in_client_socket, asio::ip::tcp::socket&& in_server_socket, std::shared_ptr<spdlog::logger> in_logger, std::uint32_t in_connection_count, std::uint32_t in_timeout, const std::string& in_rsa_key)
	:
	strand(in_client_socket.get_io_service()),
	client_socket(std::move(in_client_socket)),
	server_socket(std::move(in_server_socket)),
	
	resolver(this->client_socket.get_io_service()),
	connection_state(proxy_connection_state::ready),
	timeout(std::chrono::seconds(in_timeout)),
	logger(in_logger),
	connection_count(in_connection_count),
	logger_prefix("connection " +std::to_string(in_connection_count) + ": "),
	rsa_key(in_rsa_key)
	{
		for (int i = 0; i < static_cast<uint32_t>(timer_type::max); i++)
		{
			timers.push_back(std::make_shared< asio::basic_waitable_timer<std::chrono::steady_clock>>(client_socket.get_io_service()));
		}
	}
	std::shared_ptr<http_proxy_connection> http_proxy_connection::create(asio::ip::tcp::socket&& _in_client_socket, asio::ip::tcp::socket&& _in_server_socket, std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_idx, std::uint32_t _in_timeout, const std::string& in_rsa_key)
	{
		return std::make_shared<http_proxy_connection>(std::move(_in_client_socket), std::move(_in_server_socket), logger, in_connection_idx, _in_timeout, in_rsa_key);
	}

	void http_proxy_connection::report_error(http_parser_result _status)
	{
		auto error_detail = from_praser_result_to_description(_status);
		report_error(std::to_string(std::get<0>(error_detail)), std::get<1>(error_detail), std::get<2>(error_detail));
	}
	void http_proxy_connection::close_connection()
	{
		error_code ec;
		if (this->server_socket.is_open())
		{
			this->server_socket.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
			this->server_socket.close(ec);
		}
		if (this->client_socket.is_open())
		{
			this->client_socket.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
			this->client_socket.close(ec);
		}
	}
	void http_proxy_connection::report_error(const std::string& status_code, const std::string& status_description, const std::string& error_message)
	{
		logger->warn("{} report error status_code {} status_description {} error_message {}", logger_prefix, status_code, status_description, error_message);
		close_connection();
	}
	void http_proxy_connection::on_timeout(timer_type _cur_timer_type)
	{
		logger->info("{} on_timeout for timer {}", logger_prefix, static_cast<uint32_t>(_cur_timer_type));
		if (this->connection_state == proxy_connection_state::resolve_proxy_server_address)
		{
			this->resolver.cancel();
		}
		else
		{
			logger->warn("{} on_timeout shutdown connection", logger_prefix);
			close_connection();
		}
	}
	void http_proxy_connection::on_error(const error_code& error)
	{
		logger->warn("{} error shutdown connection {}", logger_prefix, error.message());
		this->cancel_all_timers();
		close_connection();
	}
	void http_proxy_connection::cancel_all_timers()
	{
		logger->warn("{} cancel all timers", logger_prefix);
		for (auto& one_timer : timers)
		{
			std::size_t ret = one_timer->cancel();
			assert(ret <= 1);
		}
		return;
	}
	bool http_proxy_connection::cancel_timer(timer_type _cur_timer_type)
	{
		logger->debug("{} cancel_timer {}", logger_prefix, static_cast<uint32_t>(_cur_timer_type));
		std::size_t ret = this->timers[static_cast<uint32_t>(_cur_timer_type)]->cancel();
		assert(ret <= 1);
		return ret == 1;
	}
	void http_proxy_connection::set_timer(timer_type _cur_timer_type)
	{
		logger->debug("{} set_timer {}", logger_prefix, static_cast<uint32_t>(_cur_timer_type));
		auto& cur_timer = this->timers[static_cast<uint32_t>(_cur_timer_type)];
		if (cur_timer->expires_from_now(this->timeout) != 0)
		{
			assert(false);
		}
		auto self(this->shared_from_this());
		cur_timer->async_wait(this->strand.wrap([this, self, _cur_timer_type](const error_code& error)
		{
			if (error != asio::error::operation_aborted)
			{
				this->on_timeout(_cur_timer_type);
			}
		}));
	}
	void http_proxy_connection::async_connect_to_server(std::string server_host, std::uint32_t server_port)
	{
		auto self(this->shared_from_this());
		asio::ip::tcp::resolver::query query(server_host, std::to_string(server_port));
		this->connection_state = proxy_connection_state::resolve_proxy_server_address;
		this->set_timer(timer_type::resolve);
		this->resolver.async_resolve(query, [this, self](const error_code& error, asio::ip::tcp::resolver::iterator iterator)
		{
			if (this->cancel_timer(timer_type::resolve))
			{
				if (!error)
				{
					on_resolved(iterator);
				}
				else
				{
					logger->warn("{} fail to resolve server {}", logger_prefix, iterator->host_name());
					this->on_error(error);
				}
			}
		});
	}
	void http_proxy_connection::on_resolved(asio::ip::tcp::resolver::iterator endpoint_iterator)
	{
		auto self = shared_from_this();
		this->connection_state = proxy_connection_state::connecte_to_proxy_server;
		this->set_timer(timer_type::connect);
		this->server_socket.async_connect(*endpoint_iterator, this->strand.wrap([this, self, host = endpoint_iterator->host_name()](const error_code& error)
		{
			if (this->cancel_timer(timer_type::connect))
			{
				if (!error)
				{
					this->on_server_connected();
				}
				else
				{
					logger->warn("{} fail to connect to server {}", logger_prefix, host);
					this->on_error(error);
				}
			}
		}));
	}
	bool http_proxy_connection::init_cipher(const std::string& cipher_name, const std::string& rsa_pub_key)
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
		if (cipher_name.size() > 7 && std::equal(cipher_name.begin(), cipher_name.begin() + 3, "aes"))
		{
			// aes
			std::vector<unsigned char> ivec(16);
			std::vector<unsigned char> key_vec;
			aes_generator::generate(cipher_name, cipher_code, ivec, key_vec, encryptor, decryptor);
			std::copy(ivec.cbegin(), ivec.cend(), cipher_info_raw.begin() + 7);
			std::copy(key_vec.cbegin(), key_vec.cend(), cipher_info_raw.begin() + 23);
		}

		if (!encryptor || !decryptor)
		{
			return false;
		}

		// 5 cipher code
		cipher_info_raw[5] = static_cast<unsigned char>(cipher_code);

		// 6 zero

		rsa rsa_pub(rsa_pub_key);
		if (rsa_pub.modulus_size() < 128)
		{
			logger->warn("{} invalid rsa public key", logger_prefix);
			return false;
		}

		encrypted_cipher_info.resize(rsa_pub.modulus_size());
		if (encrypted_cipher_info.size() != rsa_pub.encrypt(cipher_info_raw.size(), cipher_info_raw.data(), encrypted_cipher_info.data(), rsa_padding::pkcs1_oaep_padding))
		{
			logger->warn("{} invalid rsa encrypt size", logger_prefix);
			return false;
		}
		return true;
	}
	bool http_proxy_connection::accept_cipher(const unsigned char* cipher_data, std::size_t cipher_size)
	{
		if (cipher_size != this->rsa_key.modulus_size())
		{
			return false;
		}
		std::vector<unsigned char> decrypted_cipher_info(this->rsa_key.modulus_size());

		if (86 != this->rsa_key.decrypt(this->rsa_key.modulus_size(), cipher_data, decrypted_cipher_info.data(), rsa_padding::pkcs1_oaep_padding))
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
		return true;
	}

	void http_proxy_connection::async_read_data_from_server(bool set_timer, std::size_t at_least_size, std::size_t at_most_size)
	{
		auto self(this->shared_from_this());
		if (set_timer)
		{
			this->set_timer(timer_type::up_read);
		}
		asio::async_read(this->server_socket,
								asio::buffer(&this->server_read_buffer[0], at_most_size),
								asio::transfer_at_least(at_least_size),
								this->strand.wrap([this, self](const error_code& error, std::size_t bytes_transferred)
		{
			if (this->cancel_timer(timer_type::up_read))
			{
				if (!error)
				{
					this->on_server_data_arrived(bytes_transferred);
				}
				else
				{
					logger->warn("{} report error at {}", logger_prefix, "async_read_data_from_server");
					this->on_error(error);
				}
			}
		})
								);
	}

	void http_proxy_connection::async_read_data_from_client(bool set_timer, std::size_t at_least_size, std::size_t at_most_size)
	{
		assert(at_least_size <= at_most_size && at_most_size <= BUFFER_LENGTH);
		auto self(this->shared_from_this());
		if(set_timer)
		{
		}
		this->set_timer(timer_type::down_read);
		
		asio::async_read(this->client_socket,
								asio::buffer(&this->client_read_buffer[0], at_most_size),
								asio::transfer_at_least(at_least_size),
								this->strand.wrap([this, self](const error_code& error, std::size_t bytes_transferred)
		{
			if (this->cancel_timer(timer_type::down_read))
			{
				if (!error)
				{
					this->on_client_data_arrived(bytes_transferred);
				}
				else
				{
					logger->warn("{} report error at {}", logger_prefix, "async_read_data_from_client");
					this->on_error(error);
				}
			}
		})
								);
	}

	void http_proxy_connection::async_send_data_to_server(const unsigned char* write_buffer, std::size_t offset, std::size_t size)
	{
		logger->debug("{} async_send_data_to_server with data size {}", logger_prefix, size);
		async_send_data_to_server_impl(write_buffer, offset, size, size);
	}
	void http_proxy_connection::async_send_data_to_server_impl(const unsigned char* write_buffer, std::size_t offset, std::size_t remain_size, std::size_t total_size)
	{
		auto self(this->shared_from_this());
		this->set_timer(timer_type::up_send);

		this->server_socket.async_write_some(asio::buffer(write_buffer + offset, remain_size),
			this->strand.wrap([this, self, write_buffer, offset, remain_size, total_size](const error_code& error, std::size_t bytes_transferred)
		{
			if (this->cancel_timer(timer_type::up_send))
			{
				if (!error)
				{
					this->connection_context.reconnect_on_error = false;
					if (bytes_transferred < remain_size)
					{
						logger->debug("{} send to server with bytes transferred {}", logger_prefix, bytes_transferred);
						this->async_send_data_to_server_impl(write_buffer, offset + bytes_transferred, remain_size - bytes_transferred, total_size);
					}
					else
					{
						logger->debug("{} send to server with size {}", logger_prefix, total_size);
						this->on_server_data_send(total_size);
					}
				}
				else
				{
					logger->warn("{} report error at {}", logger_prefix, "async_send_data_to_server");
					this->on_error(error);
				}
			}
		})
		);
	}

	void http_proxy_connection::async_send_data_to_client(const unsigned char* write_buffer, std::size_t offset, std::size_t size)
	{
		async_send_data_to_client_impl(write_buffer, offset, size, size);
	}
	void http_proxy_connection::async_send_data_to_client_impl(const unsigned char* write_buffer, std::size_t offset, std::size_t remain_size, std::size_t total_size)
	{
		auto self(this->shared_from_this());
		this->set_timer(timer_type::down_send);

		this->client_socket.async_write_some(asio::buffer(write_buffer + offset, remain_size),
			this->strand.wrap([this, self, write_buffer, offset, remain_size, total_size](const error_code& error, std::size_t bytes_transferred)
		{
			if (this->cancel_timer(timer_type::down_send))
			{
				if (!error)
				{
					if (bytes_transferred < remain_size)
					{
						logger->debug("{} send to client with bytes transferred {}", logger_prefix, bytes_transferred);
						this->async_send_data_to_client_impl(write_buffer, offset + bytes_transferred, remain_size - bytes_transferred, total_size);
					}
					else
					{
						logger->debug("{} send to client with size {}", logger_prefix, total_size);
						this->on_client_data_send(total_size);
					}
				}
				else
				{
					logger->warn("{} report error at {}", logger_prefix, "async_send_data_to_client");
					this->on_error(error);
				}
			}
		})
		);

	}

	http_proxy_connection::~http_proxy_connection()
	{
		close_connection();
	}
	void http_proxy_connection::on_client_data_arrived(std::size_t bytes_transferred)
	{
		return;
	}
	void http_proxy_connection::on_server_data_arrived(std::size_t bytes_transferred)
	{
		return;
	}
	void http_proxy_connection::on_server_data_send(std::size_t bytes_transferred)
	{
		return;
	}
	void http_proxy_connection::on_client_data_send(std::size_t bytes_transferred)
	{
		return;
	}
	void http_proxy_connection::on_server_connected()
	{
		return;
	}
	void http_proxy_connection::start()
	{
		return;
	}
}
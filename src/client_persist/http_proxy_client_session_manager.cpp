#include "http_proxy_client_session_manager.hpp"
#include "http_proxy_client_config.hpp"
namespace http_proxy
{
    http_proxy_client_session_manager::http_proxy_client_session_manager(asio::io_context& in_io, std::shared_ptr<socket_wrapper> in_client_socket, std::shared_ptr<socket_wrapper> in_server_socket, std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count):
    http_proxy_session_manager(in_io, std::move(in_client_socket), std::move(in_server_socket), logger, in_connection_count, http_proxy_client_config::get_instance().get_timeout(), http_proxy_client_config::get_instance().get_rsa_public_key(), false),
		_ping_timer(in_io)
    {

    }
	std::shared_ptr<http_proxy_client_session_manager> http_proxy_client_session_manager::create(asio::io_context& in_io, std::shared_ptr<socket_wrapper> in_client_socket, std::shared_ptr<socket_wrapper> in_server_socket, std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count)
	{
		return std::make_shared<http_proxy_client_session_manager>(in_io, std::move(in_client_socket), std::move(in_server_socket), logger, in_connection_count);
	}
    void http_proxy_client_session_manager::start()
    {
		const auto& config_instance = http_proxy_client_config::get_instance();
        if(!init_cipher(config_instance.get_cipher(), config_instance.get_rsa_public_key()))
        {
			logger->warn("{} fail to init cipher", logger_prefix);
            close_connection();
            return;
        }
		connection_state = proxy_connection_state::connect_to_server;
        async_connect_to_server(config_instance.get_proxy_server_address(), config_instance.get_proxy_server_port());
    }
	void http_proxy_client_session_manager::on_server_connected()
	{
		logger->info("{} connected to proxy server established", logger_prefix);
		connection_state = proxy_connection_state::send_cipher_data;
		post_send_task(connection_count, connection_count, encrypted_cipher_info.data(), encrypted_cipher_info.size(), session_data_cmd::authenticate);
		this->async_read_data_from_server(true);
		std::memset(ping_buffer.data(), 0, ping_buffer.size());
		this->start_ping_timer();
	}
    void http_proxy_client_session_manager::on_control_data_arrived(std::uint32_t connection_idx, session_data_cmd cmd_type, std::uint32_t data_size, const char* buffer)
    {
		logger->info("{} on_control_data_arrived connection_idx {} cmd_type {} data_size {}", logger_prefix, connection_idx, static_cast<std::uint32_t>(cmd_type));
        switch(cmd_type)
        {
        case session_data_cmd::remove_session:
            remove_session(connection_idx);
            break;
        }
    }
	void http_proxy_client_session_manager::start_ping_timer()
	{
		return;
		if (this->_ping_timer.expires_from_now(std::chrono::seconds(10)) != 0)
		{
			logger->error("{} start_ping_timer fail", logger_prefix);
			assert(false);
		}
		auto self = std::dynamic_pointer_cast<http_proxy_client_session_manager>(this->shared_from_this());
		this->_ping_timer.async_wait(asio::bind_executor(this->strand, [this, self](const error_code& error)
		{
			if (error != asio::error::operation_aborted)
			{
				this->on_ping_timeout();
			}
		}));
	}
	void http_proxy_client_session_manager::on_ping_timeout()
	{
		logger->info("{} ping_data send", logger_prefix);
		_ping_timer.cancel();
		post_send_task(connection_count, connection_count, ping_buffer.data(), BUFFER_LENGTH / 2, session_data_cmd::ping_data);
		start_ping_timer();
	}

}
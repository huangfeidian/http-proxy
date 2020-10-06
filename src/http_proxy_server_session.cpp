#include "http_proxy_server_session.hpp"
#include "http_proxy_server_config.hpp"
#include "http_proxy_server_session_manager.hpp"

namespace http_proxy
{
    http_proxy_server_session::http_proxy_server_session(asio::io_context& in_io, asio::ip::tcp::socket&& _client_socket, asio::ip::tcp::socket&& _server_socket,std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count, std::shared_ptr<http_proxy_server_session_manager> in_session_manager, std::uint32_t in_client_session_count)
    :http_proxy_server_connection(in_io, std::move(_client_socket), std::move(_server_socket), logger, in_connection_count, "session"), 
    _session_manager(in_session_manager),
	client_session_count(in_client_session_count)
    {
        
    }

    std::shared_ptr<http_proxy_server_session> http_proxy_server_session::create(asio::io_context& in_io, asio::ip::tcp::socket&& _client_socket, asio::ip::tcp::socket&& _server_socket,std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count, std::shared_ptr<http_proxy_server_session_manager> in_session_manager, std::uint32_t in_client_session_count)
    {
        auto result = std::make_shared<http_proxy_server_session>(in_io, std::move(_client_socket), std::move(_server_socket), logger, in_connection_count, in_session_manager, in_client_session_count);
        in_session_manager->add_session(result);
		return result;
    }

	void http_proxy_server_session::start()
	{
		logger->info("{} start", logger_prefix);
		encryptor = std::make_unique<copy_encryptor>();
		decryptor = std::make_unique<copy_decryptor>();
		this->connection_context.connection_state = proxy_connection_state::read_http_request_header;
		this->async_read_data_from_client();
	}

    void http_proxy_server_session::async_read_data_from_client(bool set_timer, std::size_t at_least_size, std::size_t at_most_size)
    {
		auto the_session_manager = _session_manager.lock();
		if (!the_session_manager)
		{
			logger->warn("{} async_read_data_from_client but session_manager expire", logger_prefix);
			return;
		}
        if (set_timer)
		{
			this->set_timer(timer_type::down_read);
		}
		the_session_manager->post_read_task(shared_from_this(), at_least_size, at_most_size);
    }
	void http_proxy_server_session::async_send_data_to_client(const unsigned char* write_buffer, std::size_t offset, std::size_t size)
	{
		auto the_session_manager = _session_manager.lock();
		if (!the_session_manager)
		{
			logger->warn("{} async_send_data_to_client but session_manager expire", logger_prefix);
			return;
		}
		set_timer(timer_type::down_send);
		the_session_manager->post_send_task(connection_count, client_session_count, write_buffer + offset, size);
	}
	void http_proxy_server_session::on_client_data_arrived(std::size_t bytes_transferred)
	{
		cancel_timer(timer_type::down_read);
		http_proxy_server_connection::on_client_data_arrived(bytes_transferred);
	}
	void http_proxy_server_session::on_client_data_send(std::size_t bytes_transferred)
	{
		cancel_timer(timer_type::down_send);
		http_proxy_server_connection::on_client_data_send(bytes_transferred);
	}
	void http_proxy_server_session::close_connection()
	{
		auto the_session_manager = _session_manager.lock();
		if (!the_session_manager)
		{
			logger->warn("{} close_connection but session_manager expire", logger_prefix);
		}
		else
		{
			the_session_manager->remove_session(connection_count);
		}
		http_proxy_server_connection::close_connection();
	}
}
#include "http_proxy_client_session.hpp"
#include "http_proxy_client_config.hpp"
#include "http_proxy_client_session_manager.hpp"
namespace azure_proxy
{
    http_proxy_client_session::http_proxy_client_session(asio::ip::tcp::socket&& ua_socket, asio::ip::tcp::socket&& _server_socket,std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count, std::weak_ptr< http_proxy_client_session_manager> in_session_manager)
    :http_proxy_client_connection(std::move(ua_socket), std::move(_server_socket), logger, in_connection_count), 
    _session_manager(in_session_manager)
    {
        
    }

   std::shared_ptr<http_proxy_client_session> http_proxy_client_session::create(asio::ip::tcp::socket&& ua_socket, asio::ip::tcp::socket&& _server_socket,std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count, std::weak_ptr< http_proxy_client_session_manager> in_session_manager)
    {
	   auto the_session_manager = in_session_manager.lock();
	   if (!the_session_manager)
	   {
		   logger->warn("http_proxy_client_session::create with invalid session manager");
		   return std::shared_ptr< http_proxy_client_session>();
	   }
        auto result = std::make_shared<http_proxy_client_session>(std::move(ua_socket), std::move(_server_socket), logger, in_connection_count, in_session_manager);
		the_session_manager->add_session(result);
		return result;
    }
    http_proxy_client_session::~http_proxy_client_session()
    {
		auto the_session_manager = _session_manager.lock();
		if (the_session_manager)
		{
			the_session_manager->remove_session(connection_count);
		}
        
    }
    void http_proxy_client_session::async_read_data_from_server(bool set_timer, std::size_t at_least_size, std::size_t at_most_size)
    {
		auto the_session_manager = _session_manager.lock();
		if (!the_session_manager)
		{
			logger->warn("{} async_read_data_from_server with session_manager expire", logger_prefix);
			close_connection();
			return;
		}
        if (set_timer)
		{
			this->set_timer();
		}
		the_session_manager->post_read_task(shared_from_this(), server_read_buffer.data(), at_least_size, at_most_size);
    }
	void http_proxy_client_session::async_send_data_to_server(std::size_t offset, std::size_t size)
	{
		auto the_session_manager = _session_manager.lock();
		if (!the_session_manager)
		{
			logger->warn("{} async_send_data_to_server with session_manager expire", logger_prefix);
			close_connection();
			return;
		}
		set_timer();
		the_session_manager->post_send_task(connection_count, connection_count, server_send_buffer.data() + offset, size);
	}
	void http_proxy_client_session::close_connection()
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
		http_proxy_client_connection::close_connection();
	}

}
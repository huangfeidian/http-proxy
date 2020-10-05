#include "http_proxy_client_session.hpp"
#include "http_proxy_client_config.hpp"
#include "http_proxy_client_session_manager.hpp"
namespace http_proxy
{
    http_proxy_client_session::http_proxy_client_session(asio::ip::tcp::socket&& ua_socket, asio::ip::tcp::socket&& _server_socket,std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count, std::weak_ptr< http_proxy_client_session_manager> in_session_manager)
    :http_proxy_client_connection(std::move(ua_socket), std::move(_server_socket), logger, in_connection_count, "session"),
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
   void http_proxy_client_session::start()
   {
	   encryptor = std::make_unique<copy_encryptor>();
	   decryptor = std::make_unique<copy_decryptor>();
	   on_server_connected();
   }
   void http_proxy_client_session::on_server_connected()
   {
	   logger->info("{} on_server_connected", logger_prefix);
	   async_read_data_from_server(false);
	   return;
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
			this->set_timer(timer_type::up_read);
		}
		the_session_manager->post_read_task(shared_from_this(), at_least_size, at_most_size);
    }
	void http_proxy_client_session::async_send_data_to_server(const unsigned char* write_buffer, std::size_t offset, std::size_t size)
	{
		auto the_session_manager = _session_manager.lock();
		if (!the_session_manager)
		{
			logger->warn("{} async_send_data_to_server with session_manager expire", logger_prefix);
			close_connection();
			return;
		}
		set_timer(timer_type::up_send);
		the_session_manager->post_send_task(connection_count, connection_count, write_buffer + offset, size);
	}
	void http_proxy_client_session::on_server_data_arrived(std::size_t bytes_transferred)
	{
		cancel_timer(timer_type::up_read);
		http_proxy_client_connection::on_server_data_arrived(bytes_transferred);
	}
	void http_proxy_client_session::on_server_data_send(std::size_t bytes_transferred)
	{
		cancel_timer(timer_type::up_send);
		http_proxy_client_connection::on_server_data_send(bytes_transferred);
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
#include "http_proxy_client_session.hpp"
#include "http_proxy_client_config.hpp"

namespace azure_proxy
{
    http_proxy_client_session::http_proxy_client_session(asio::ip::tcp::socket&& ua_socket, asio::ip::tcp::socket&& _server_socket,std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count, http_proxy_client_session_manager& in_session_manager)
    :http_proxy_client_connection(std::move(ua_socket), std::move(_server_socket), in_connection_count, http_proxy_client_config::get_instance().get_timeout()), 
    _session_manager(in_session_manager)
    {
        
    }

    static std::shared_ptr<http_proxy_client_session> http_proxy_client_session::create(asio::ip::tcp::socket&& ua_socket, asio::ip::tcp::socket&& _server_socket,std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count, http_proxy_client_session_manager& in_session_manager)
    {
        auto result = std::make_shared<http_proxy_client_session>(std::move(ua_socket), std::move(_server_socket),  logger, in_connection_count, in_session_manager);
        _session_manager.add_session(result);
		return result;
    }
    http_proxy_client_session::~http_proxy_client_session
    {
        _session_manager.remove_session(connection_count);
    }
    void http_proxy_client_session::async_read_data_from_server(bool set_timer, std::size_t at_least_size, std::size_t at_most_size)
    {
        if (set_timer)
		{
			this->set_timer();
		}
        _session_manager.post_read_task(shared_from_this(), server_read_buffer.data(), at_least_size, at_most_size);
    }
	void http_proxy_client_session::async_send_data_to_server(std::size_t offset, std::size_t size)
	{
		set_timer();
		_session_manager.post_send_task(shared_from_this(), server_send_buffer.data(), offset, size);
	}

}
#include "http_proxy_server_session.hpp"
#include "http_proxy_server_config.hpp"
#include "http_proxy_server_session_manager.hpp"

namespace azure_proxy
{
    http_proxy_server_session::http_proxy_server_session(asio::ip::tcp::socket&& _client_socket, asio::ip::tcp::socket&& _server_socket,std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count, http_proxy_server_session_manager& in_session_manager)
    :http_proxy_server_connection(std::move(_client_socket), std::move(_server_socket), logger, in_connection_count), 
    _session_manager(in_session_manager)
    {
        
    }

    std::shared_ptr<http_proxy_server_session> http_proxy_server_session::create(asio::ip::tcp::socket&& _client_socket, asio::ip::tcp::socket&& _server_socket,std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count, http_proxy_server_session_manager& in_session_manager)
    {
        auto result = std::make_shared<http_proxy_server_session>(std::move(_client_socket), std::move(_server_socket), logger, in_connection_count, in_session_manager);
        in_session_manager.add_session(result);
		return result;
    }
    http_proxy_server_session::~http_proxy_server_session()
    {
        _session_manager.remove_session(connection_count);
    }
    void http_proxy_server_session::async_read_data_from_client(bool set_timer, std::size_t at_least_size, std::size_t at_most_size)
    {
        if (set_timer)
		{
			this->set_timer();
		}
        _session_manager.post_read_task(shared_from_this(), server_read_buffer.data(), at_least_size, at_most_size);
    }
	void http_proxy_server_session::async_send_data_to_client(std::size_t offset, std::size_t size)
	{
		set_timer();
		_session_manager.post_send_task(connection_count, server_send_buffer.data() + offset, size);
	}
}
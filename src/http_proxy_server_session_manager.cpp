#include "http_proxy_server_session_manager.hpp"
#include "http_proxy_server_config.hpp"
namespace azure_proxy
{
    http_proxy_server_session_manager::http_proxy_server_session_manager(asio::ip::tcp::socket&& in_client_socket, asio::ip::tcp::socket&& in_server_socket, std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count):
    http_proxy_session_manager(std::move(in_client_socket), std::move(in_server_socket), logger, in_connection_count, http_proxy_server_config::get_instance().get_timeout(), http_proxy_server_config::get_instance().get_rsa_private_key(), false)
    {

    }
	std::shared_ptr<http_proxy_server_session_manager> http_proxy_server_session_manager::create(asio::ip::tcp::socket&& in_client_socket, asio::ip::tcp::socket&& in_server_socket, std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count)
	{
		return std::make_shared<http_proxy_server_session_manager>(std::move(in_client_socket), std::move(in_server_socket), logger, in_connection_count);
	}
    void http_proxy_server_session_manager::start()
    {
        this->connection_context.connection_state = proxy_connection_state::read_cipher_data;
		this->async_read_data_from_client(true, 1, std::min<std::uint32_t>(this->rsa_key.modulus_size(), BUFFER_LENGTH));
		logger->info("{} new connection start", logger_prefix);
    }
    void http_proxy_server_session_manager::on_control_data_arrived(std::uint32_t connection_idx, session_data_cmd cmd_type, std::uint32_t data_size, const char* buffer)
    {

    }

}
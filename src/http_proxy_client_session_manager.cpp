#include "http_proxy_client_session_manager.hpp"
#include "http_proxy_client_config.hpp"
namespace azure_proxy
{
    http_proxy_client_session_manager::http_proxy_client_session_manager(asio::ip::tcp::socket&& in_client_socket, asio::ip::tcp::socket&& in_server_socket, std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count):
    http_proxy_session_manager(std::move(in_client_socket), std::move(in_server_socket), logger, in_connection_count, http_proxy_client_config::get_instance().get_timeout(), http_proxy_client_config::get_instance().get_rsa_public_key(), true)
    {

    }
	std::shared_ptr<http_proxy_client_session_manager> http_proxy_client_session_manager::create(asio::ip::tcp::socket&& in_client_socket, asio::ip::tcp::socket&& in_server_socket, std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count)
	{
		return std::make_shared<http_proxy_client_session_manager>(std::move(in_client_socket), std::move(in_server_socket), logger, in_connection_count);
	}
    void http_proxy_client_session_manager::start()
    {
		const auto& config_instance = http_proxy_client_config::get_instance();
        if(!init_cipher(config_instance.get_cipher(), config_instance.get_rsa_public_key()))
        {
            close_connection();
            return;
        }
		connection_state = proxy_connection_state::connect_to_origin_server;
        async_connect_to_server(config_instance.get_proxy_server_address(), config_instance.get_proxy_server_port());
    }
	void http_proxy_client_session_manager::on_server_connected()
	{
		logger->info("{} connected to proxy server established", logger_prefix);
		connection_state = proxy_connection_state::send_cipher_data;
		post_send_task(connection_count, encrypted_cipher_info.data(), encrypted_cipher_info.size(), session_data_cmd::authenticate);
		connection_state = proxy_connection_state::session_tranfer;
		this->async_read_data_from_server(false);
	}
    void http_proxy_client_session_manager::on_control_data_arrived(std::uint32_t connection_idx, session_data_cmd cmd_type, std::uint32_t data_size, const char* buffer)
    {
        switch(cmd_type)
        {
        case session_data_cmd::remove_session:
            remove_session(connection_idx);
            break;
        }
    }

}
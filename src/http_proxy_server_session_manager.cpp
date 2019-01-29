#include "http_proxy_server_session_manager.hpp"
#include "http_proxy_server_config.hpp"
namespace azure_proxy
{
    http_proxy_server_session_manager::http_proxy_server_session_manager(asio::io_service& _in_io_service, std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count):
    http_proxy_session_manager(_in_io_service, logger, in_connection_count, http_proxy_server_config::get_instance().get_timeout(), true)
    {

    }
    void http_proxy_server_session_manager::start()
    {
        this->connection_context.connection_state = proxy_connection_state::read_cipher_data;
		this->async_read_data_from_client(1, std::min<std::size_t>(this->rsa_pri.modulus_size(), BUFFER_LENGTH));
		logger->info("{} new connection start", logger_prefix);
    }
    void http_proxy_server_session_manager::on_control_data_arrived(std::uint32_t connection_idx, session_data_cmd cmd_type, std::uint32_t data_size, const char* buffer)
    {

    }

}
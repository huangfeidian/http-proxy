#include "http_proxy_client_session_manager.hpp"
#include "http_proxy_client_config.hpp"
namespace azure_proxy
{
    http_proxy_client_session_manager::http_proxy_client_session_manager(asio::io_service& _in_io_service, std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count):
    http_proxy_session_manager(_in_io_service, logger, in_connection_count, http_proxy_client_config::get_instance().get_timeout(), true)
    {

    }
    void http_proxy_client_session_manager::start()
    {
        if(!http_proxy_client_config::init_cipher_for_connection(*this))
        {
            shutdown_connection();
            return;
        }
        async_connect_to_server(http_proxy_client_config::get_instance().get_proxy_server_address(), http_proxy_client_config::get_instance().get_proxy_server_port());
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
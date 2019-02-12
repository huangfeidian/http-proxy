#include "http_proxy_server_session_manager.hpp"
#include "http_proxy_server_config.hpp"
#include "http_proxy_server_session.hpp"
namespace azure_proxy
{
    http_proxy_server_session_manager::http_proxy_server_session_manager(asio::ip::tcp::socket&& in_client_socket, asio::ip::tcp::socket&& in_server_socket, std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count):
    http_proxy_session_manager(std::move(in_client_socket), std::move(in_server_socket), logger, in_connection_count, http_proxy_server_config::get_instance().get_timeout(), http_proxy_server_config::get_instance().get_rsa_private_key(), true)
    {

    }
	std::shared_ptr<http_proxy_server_session_manager> http_proxy_server_session_manager::create(asio::ip::tcp::socket&& in_client_socket, asio::ip::tcp::socket&& in_server_socket, std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count)
	{
		return std::make_shared<http_proxy_server_session_manager>(std::move(in_client_socket), std::move(in_server_socket), logger, in_connection_count);
	}
    void http_proxy_server_session_manager::start()
    {
        this->connection_context.connection_state = proxy_connection_state::read_cipher_data;
		this->async_read_data_from_client(true, 1, std::min<std::uint32_t>(this->rsa_key.modulus_size() + DATA_HEADER_LEN, BUFFER_LENGTH));
		logger->info("{} new connection start", logger_prefix);
    }
    void http_proxy_server_session_manager::on_control_data_arrived(std::uint32_t connection_idx, session_data_cmd cmd_type, std::uint32_t data_size, const unsigned char* buffer)
    {
		logger->info("{} on_control_data_arrived connection_idx {} cmd_type {}", logger_prefix, connection_idx, static_cast<std::uint32_t>(cmd_type));
		switch (cmd_type)
		{
		case session_data_cmd::authenticate:
			if (!accept_cipher(buffer, data_size))
			{
				logger->warn("{} accept_cipher fail", logger_prefix);
				close_connection();
				return;
			}
			break;
		case session_data_cmd::ping_data:
			post_send_task(connection_count, connection_count, client_send_buffer.data(), BUFFER_LENGTH / 2, session_data_cmd::pong_data);
			break;
		case session_data_cmd::new_session:
		{
			auto& the_io_service = client_socket.get_io_service();
			auto cur_connection_count = http_proxy_server_config::get_instance().increase_connection_count();
			auto new_session = http_proxy_server_session::create(std::move(asio::ip::tcp::socket(the_io_service)), std::move(asio::ip::tcp::socket(the_io_service)), logger, cur_connection_count, std::dynamic_pointer_cast<http_proxy_server_session_manager>(shared_from_this()), connection_idx);
			add_session(new_session);
			mapped_session[connection_idx] = cur_connection_count;
			new_session->start();
		}
		break;


			
		case session_data_cmd::remove_session:
		{
			auto local_session_iter = mapped_session.find(connection_idx);
			if (local_session_iter == mapped_session.end())
			{
				logger->warn("{} invalid remove_session with connection_idx {}", logger_prefix, connection_idx);
			}
			else
			{
				auto local_session_idx = local_session_iter->second;
				mapped_session.erase(connection_idx);
				remove_session(local_session_idx);
			}
		}
			break;
		default:
			logger->warn("{} invalid session_data_cmd {}", logger_prefix, static_cast<std::uint32_t>(cmd_type));
		}
    }
}
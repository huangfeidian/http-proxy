#pragma once
#include "http_proxy_session_manager.hpp"


namespace http_proxy
{
	class http_proxy_client_session_manager: public http_proxy_session_manager
	{
	public:

		http_proxy_client_session_manager(asio::io_context& in_io, std::shared_ptr<socket_wrapper>&& in_client_socket, std::shared_ptr<socket_wrapper>&& in_server_socket, std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count);
		void start();
		void on_server_connected();
		void on_control_data_arrived(std::uint32_t connection_idx, session_data_cmd cmd_type, std::uint32_t data_size, const char * buffer);
		static std::shared_ptr<http_proxy_client_session_manager> create(asio::io_context& in_io, std::shared_ptr<socket_wrapper>&& in_client_socket, std::shared_ptr<socket_wrapper>&& in_server_socket, std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count);
	protected:
		asio::steady_timer _ping_timer;
		void start_ping_timer();
		void on_ping_timeout();
		std::array<unsigned char, BUFFER_LENGTH> ping_buffer;
	
	};
}
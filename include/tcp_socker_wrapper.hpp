#pragma once
#include "socket_wrapper.hpp"

namespace http_proxy
{
	class http_proxy_connection;
	class tcp_socket_wrapper: public socket_wrapper
	{
	protected:
		asio::ip::tcp::socket m_socket;
		asio::ip::tcp::resolver m_resolver;
	protected:
		void on_resolved(asio::ip::tcp::resolver::iterator endpoint_iterator);
		
	public:
		tcp_socket_wrapper(asio::ip::tcp::socket&& in_tcp_socket);
		~tcp_socket_wrapper() override;
		void shutdown() override;
		auto& get_socket() 
		{
			return m_socket;
		}
		void async_connect(std::string server_host, std::uint32_t server_port) override;
		void async_write_some(const asio::const_buffer& buffer, std::function<void(const asio::error_code&, std::size_t )> cb) override;
		void async_read_some(const asio::mutable_buffer& buffer, std::function<void(const asio::error_code&, std::size_t )> cb) override;
	};
}
#pragma once
#include <asio.hpp>
#include <functional>
namespace http_proxy
{
	class http_proxy_connection;
	class socket_wrapper
	{
	protected:
		http_proxy_connection* m_connection = nullptr;
	public:

		socket_wrapper()
		{

		}
		virtual void init(http_proxy_connection* in_connection)
		{
			m_connection = in_connection;
		}
		virtual bool is_open()const
		{
			return false;
		}
		socket_wrapper(const socket_wrapper& ) = delete;
		virtual std::string remote_endpoint_address()
		{
			return {};
		}
		virtual void shutdown() = 0;
		virtual ~socket_wrapper()
		{
			m_connection = nullptr;
		}

		virtual void async_connect(std::string server_host, std::uint32_t server_port) = 0;
		virtual void async_write_some(const asio::const_buffer& buffer, std::function<void(const asio::error_code&, std::size_t )>&&) = 0;
		virtual void async_read_some(const asio::mutable_buffer& buffer, std::function<void(const asio::error_code&, std::size_t )>&&) = 0;

	};
}
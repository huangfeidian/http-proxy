#include "tcp_socker_wrapper.hpp"
#include "http_proxy_connection.hpp"

namespace http_proxy
{
	tcp_socket_wrapper::tcp_socket_wrapper(asio::ip::tcp::socket&& in_tcp_socket)
	: m_socket(std::move(in_tcp_socket))
	, m_resolver(m_socket.get_executor())
	{

	}
	tcp_socket_wrapper::~tcp_socket_wrapper()
	{
		shutdown();
	}
	void tcp_socket_wrapper::shutdown()
	{
		if(m_socket.is_open())
		{
			asio::error_code ec;
			m_socket.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
			m_socket.close();
		}
	}

	void tcp_socket_wrapper::async_connect(std::string server_host, std::uint32_t server_port) 
	{
		if(!m_connection)
		{
			assert(false);
			exit(1);
			return;
		}
		m_connection->connection_state = proxy_connection_state::resolve_server_address;
		m_connection->set_timer(timer_type::resolve);
		asio::ip::tcp::resolver::query query(server_host, std::to_string(server_port));
		
		m_resolver.async_resolve(query, [this, conn = m_connection->shared_from_this(), server_host](const asio::error_code& error, asio::ip::tcp::resolver::iterator iterator)
		{
			if (m_connection->cancel_timer(timer_type::resolve))
			{
				if (!error)
				{
					on_resolved(iterator);
				}
				else
				{
					m_connection->logger->warn("{} fail to resolve server {}", m_connection->logger_prefix, server_host);
					m_connection->on_error(error);
				}
			}
		});
	}

	void tcp_socket_wrapper::on_resolved(asio::ip::tcp::resolver::iterator endpoint_iterator)
	{
		m_connection->connection_state = proxy_connection_state::connect_to_server;
		m_connection->set_timer(timer_type::connect);
		m_socket.async_connect(*endpoint_iterator, asio::bind_executor(m_connection->strand, [this, conn = m_connection->shared_from_this(), host = endpoint_iterator->host_name(), endpoint_iterator](const error_code& error) mutable
		{
			if (m_connection->cancel_timer(timer_type::connect))
			{
				if (!error)
				{
					m_connection->on_server_connected();
				}
				else
				{
					asio::error_code ec;
					m_socket.close(ec);
					if (++endpoint_iterator != asio::ip::tcp::resolver::iterator())
					{
						this->on_resolved(endpoint_iterator);
					}
					else
					{
						m_connection->logger->warn("{} fail to connect origin server {}", m_connection->logger_prefix, host);
						m_connection->on_error(error);
					}
				}
			}
		}));
	}

	void tcp_socket_wrapper::async_write_some(const asio::const_buffer& buffer, std::function<void(const asio::error_code&, std::size_t )> cb) 
	{
		m_socket.async_write_some(buffer, cb);
	}

	void tcp_socket_wrapper::async_read_some(const asio::mutable_buffer& buffer, std::function<void(const asio::error_code&, std::size_t )> cb)
	{
		m_socket.async_read_some(buffer, cb);
	}
}
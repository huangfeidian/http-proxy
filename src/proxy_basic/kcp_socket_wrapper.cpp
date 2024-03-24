#include "kcp_socket_wrapper.hpp"
#include "http_proxy_connection.hpp"

namespace http_proxy
{

	kcp_socket_wrapper::kcp_socket_wrapper(asio::ip::udp::socket&& in_socket, const std::string& in_kcp_magic)
		: m_socket(std::move(in_socket))
		, m_resolver(m_socket.get_executor())
		, m_kcp_magic(in_kcp_magic)
	{

	}

	kcp_socket_wrapper::kcp_socket_wrapper(moon::kcp::connection_ptr in_kcp_conn)
		: m_socket(in_kcp_conn->get_executor())
		, m_resolver(in_kcp_conn->get_executor())
		, m_kcp_conn(in_kcp_conn)
	{

	}

	void kcp_socket_wrapper::async_connect(std::string server_host, std::uint32_t server_port)
	{
		if (!m_connection)
		{
			assert(false);
			exit(1);
			return;
		}


		m_connection->connection_state = proxy_connection_state::resolve_server_address;
		m_connection->set_timer(timer_type::resolve);
		asio::ip::udp::resolver::query query(server_host, std::to_string(server_port));

		m_resolver.async_resolve(query, [this, conn = m_connection->shared_from_this(), server_host](const asio::error_code& error, asio::ip::udp::resolver::iterator iterator)
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

	void kcp_socket_wrapper::on_resolved(asio::ip::udp::resolver::iterator endpoint_iterator)
	{
		m_connection->connection_state = proxy_connection_state::connect_to_server;
		m_connection->set_timer(timer_type::connect);
		m_socket.async_connect(*endpoint_iterator, asio::bind_executor(m_connection->strand, [this, conn = m_connection->shared_from_this(), host = endpoint_iterator->host_name(), endpoint_iterator](const error_code& error) mutable
			{
				if (m_connection->cancel_timer(timer_type::connect))
				{
					if (!error)
					{
						on_udp_connected();
					}
					else
					{
						asio::error_code ec;
						m_socket.close(ec);
						if (++endpoint_iterator != asio::ip::udp::resolver::iterator())
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

	void kcp_socket_wrapper::on_udp_connected()
	{
		m_connection->logger->info("{} on_udp_connected", m_connection->logger_prefix);
		m_kcp_data.push_back((char)moon::kcp::packet_handshake);
		m_kcp_data.append(m_kcp_magic);
		m_socket.async_send(asio::buffer(m_kcp_data), asio::bind_executor(m_connection->strand, [this, conn = m_connection->shared_from_this()](asio::error_code ec, std::size_t bytes_transferred)
			{
				if (ec)
				{
					m_connection->logger->warn("{} fail to send handshake data to server{}", m_connection->logger_prefix);
					m_connection->on_error(ec);
					return;
				}
				m_kcp_data.clear();
				m_kcp_data.resize(4, 0);
				m_socket.async_receive(asio::buffer(m_kcp_data), asio::bind_executor(m_connection->strand, [this, conn](asio::error_code ec2, std::size_t bytes_transferred2)
					{
						if (ec2)
						{
							m_connection->logger->warn("{} fail to receive handshake data to server{}", m_connection->logger_prefix);
							m_connection->on_error(ec2);
							return;
						}
						std::uint32_t conv;
						if (bytes_transferred2 != sizeof(conv))
						{
							assert(false);
						}
						
						std::memcpy(&conv, m_kcp_data.data(), sizeof(conv));
						m_kcp_conn = std::make_shared<moon::kcp::connection>(&m_socket, conv, m_dest_endpoint, false);
						m_kcp_conn->start_client();
						m_connection->on_server_connected();
					}));
			}));
	}

	void kcp_socket_wrapper::async_write_some(const asio::const_buffer& buffer, std::function<void(const asio::error_code&, std::size_t)>&& handler)
	{
		if (!m_kcp_conn)
		{
			assert(false);
			exit(1);
		}
		m_kcp_conn->async_write(buffer, std::move(handler));
	}

	void kcp_socket_wrapper::async_read_some(const asio::mutable_buffer& buffer, std::function<void(const asio::error_code&, std::size_t)>&& handler)
	{
		if (!m_kcp_conn)
		{
			assert(false);
			exit(1);
		}
		m_kcp_conn->async_read_some(buffer, std::move(handler));
	}

	void kcp_socket_wrapper::shutdown()
	{
		if (!m_socket.is_open())
		{
			return;
		}
		if (m_kcp_conn)
		{
			std::error_code ignore;
			m_kcp_conn->close(ignore);
			m_kcp_conn.reset();
		}
		
		if (!m_kcp_magic.empty())
		{
			// 只有客户端到服务端的连接需要关闭
			std::error_code ignore;
			m_socket.close(ignore);
		}

	}

	kcp_socket_wrapper::~kcp_socket_wrapper()
	{
		shutdown();
	}
}
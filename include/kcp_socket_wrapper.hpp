#pragma once

#include "kcp.hpp"

#include "socket_wrapper.hpp"

namespace http_proxy
{
	class kcp_socket_wrapper : public socket_wrapper
	{
		asio::ip::udp::socket m_socket;
		asio::ip::udp::resolver m_resolver;
		std::shared_ptr<moon::kcp::connection> m_kcp_conn;
		asio::ip::udp::endpoint m_dest_endpoint;
		std::string m_kcp_data;
		std::string m_kcp_magic;
		void on_resolved(asio::ip::udp::resolver::iterator endpoint_iterator);
		void on_udp_connected();

	public:
		kcp_socket_wrapper(asio::ip::udp::socket&& in_socket, const std::string& in_kcp_magic);
		kcp_socket_wrapper(std::shared_ptr<moon::kcp::connection> m_kcp_conn);

		void async_connect(std::string server_host, std::uint32_t server_port) override;
		void async_write_some(const asio::const_buffer& buffer, std::function<void(const asio::error_code&, std::size_t)>&&) override;
		void async_read_some(const asio::mutable_buffer& buffer, std::function<void(const asio::error_code&, std::size_t)>&&) override;

		bool is_open() const override
		{
			return m_kcp_conn && m_kcp_conn->get_socket().is_open();
		}
		~kcp_socket_wrapper() override;

		void shutdown() override;
	};
}
#pragma once

#include "kcp/ikcp.h"

#include "socket_wrapper.hpp"
#include "config.hpp"

#include <spdlog/logger.h>
#include <memory>
#include <queue>
#include <unordered_map>
#include <unordered_set>

namespace http_proxy
{
	enum class kcp_packet_type
	{
		handshake = 1,
		keepalive = 2,
		data = 3,
		disconnect = 4,
		max
	};
	enum class connection_state
	{
		idle = 0,
		opened = 1,
		closed = 2,
	};
	class kcp_socket_wrapper : public socket_wrapper
	{
		friend class kcp_listener;
	protected:




		struct kcp_obj_deleter { void operator()(ikcpcb* p) { ikcp_release(p); } };
		using kcp_context_ptr = std::unique_ptr<ikcpcb, kcp_obj_deleter>;

		connection_state m_state = connection_state::idle;

		std::shared_ptr<asio::ip::udp::socket> m_socket;
		
		asio::ip::udp::endpoint m_remote_endpoint;
		kcp_context_ptr m_kcp_ctx;
		

		std::vector<char> m_send_buffer;
		std::vector<char> m_read_buffer;
		asio::mutable_buffer m_read_dest;
		std::function<void(const asio::error_code&, std::size_t)> m_send_cb;
		std::function<void(const asio::error_code&, std::size_t)> m_read_cb;
		std::uint32_t m_kcp_conn_index = 0;
		static constexpr std::uint32_t m_idle_send_packet_count = 128;
		time_t m_next_kcp_tick = 0; // 计算出来的下一次应该tick update的时间
		time_t m_last_recv_tick = 0; // 上次接收数据的时间 用来计算timeout
		const time_t m_update_interval = 5; // milliseconds
		const time_t m_timeout_duration = 30 * 1000;// milliseconds 接收数据的超时


		time_t do_update(time_t now);

		virtual void async_write_some_impl(const char* buf, std::uint32_t offset, std::uint32_t remain_sz) = 0;

		virtual void async_read_some_impl() = 0;

		void init_kcp_ctx();

		// udp每次收到数据时 都是以一个整的包接收的 不会出现包被拆散或者合并的情况
		void on_receive(std::uint64_t packet_sz, time_t t);
		
		


		virtual void close_impl() = 0;
	public:
		virtual bool is_server() const = 0;
		kcp_socket_wrapper(std::shared_ptr<asio::ip::udp::socket> in_socket);

		void check_read_finish();
		void check_write_finish();

		// kcp的发送并不是立即发送 而是当发送队列小于特定值时即认为已经发送
		void async_write_some(const asio::const_buffer& buffer, std::function<void(const asio::error_code&, std::size_t)>&& cb) override;

		void async_read_some(const asio::mutable_buffer& buffer, std::function<void(const asio::error_code&, std::size_t)>&& cb) override;

		bool is_open() const override;
		connection_state get_state() const
		{
			return m_state;
		}
		std::uint32_t get_conn_idx() const
		{
			return m_kcp_conn_index;
		}
	
		~kcp_socket_wrapper() override;
		void close(const asio::error_code& ec);

	};

	class kcp_client_socket_wrapper : public kcp_socket_wrapper
	{
	protected:

		std::string m_kcp_handshake_data;

		std::string m_kcp_magic;
		asio::ip::udp::resolver m_resolver;
		asio::steady_timer m_update_timer;
		void async_write_some_impl(const char* buf, std::uint32_t offset, std::uint32_t remain_sz) override;
		void async_read_some_impl() override;
		void close_impl() override;
		void start_kcp_update_timer();
	public:
		kcp_client_socket_wrapper(std::shared_ptr<asio::ip::udp::socket> in_socket, const std::string& in_kcp_magic);
		void async_connect(std::string server_host, std::uint32_t server_port) override;
		void on_resolved(asio::ip::udp::resolver::iterator endpoint_iterator);
		void on_udp_connected();
		bool is_server() const override
		{
			return false;
		}
		void shutdown() override;
		
	};
	class kcp_server_socket_wrapper;

	class kcp_acceptor
	{
	protected:
		asio::io_context& m_ioc;
		asio::steady_timer m_update_timer;
		asio::ip::udp::endpoint m_listen_endpoint;
		std::shared_ptr<asio::ip::udp::socket> m_socket;
		std::shared_ptr<spdlog::logger> m_logger;
		std::unordered_map<asio::ip::udp::endpoint, std::shared_ptr<kcp_server_socket_wrapper>> m_client_connections;
		std::queue<std::pair<asio::ip::udp::endpoint, std::shared_ptr<std::string>>> m_send_queues;
		std::mutex m_send_queue_lock;
		const std::string m_magic;
		
		
		asio::ip::udp::endpoint m_read_from_endpoint;

		std::unordered_set<std::uint32_t> m_used_conn_idxes;
		std::vector<char> m_read_buffer;
		time_t m_now = 0;
		std::uint32_t m_conn_counter = 0;
		
		const time_t timeout_duration = 30 * 1000; // milliseconds
		const time_t update_gap = 5;// milliseconds
		std::function<void(std::shared_ptr< kcp_server_socket_wrapper>)> m_accept_cb;
	protected:
		std::uint32_t make_conn_idx();
		void update();
		void do_receive();
		void after_send();
	public:
		kcp_acceptor(asio::io_context& in_ioc, asio::ip::udp::endpoint in_listen_endpoint, std::shared_ptr<spdlog::logger> in_logger, const std::string& in_magic);
		void async_accept(std::function<void(std::shared_ptr< kcp_server_socket_wrapper>)> accept_cb);
		void do_send(asio::ip::udp::endpoint send_to_endpoint, std::string_view data);
		void close();

	};
	class kcp_server_socket_wrapper : public kcp_socket_wrapper
	{
		friend class kcp_listener;
	protected:
		// kcp不是线程安全的 所以所有操作都要用mutex保护
		std::mutex m_logic_mutex;
		kcp_acceptor& m_acceptor;

	protected:
		// 这里什么都不做 直接等待acceptor的通知
		void async_read_some_impl() override;
		void async_write_some_impl(const char* buf, std::uint32_t offset, std::uint32_t remain_sz) override;

		void close_impl() override;
	public:
		kcp_server_socket_wrapper(std::shared_ptr<asio::ip::udp::socket> in_socket, kcp_acceptor& in_acceptor, asio::ip::udp::endpoint in_remote_endpoint, std::uint32_t in_conn_idx);
		~kcp_server_socket_wrapper();
		void on_receive(const char* data, std::uint64_t size, time_t ts);
		time_t update(time_t now_ts);
		bool is_server() const override
		{
			return true;
		}
		void shutdown() override;
		void async_connect(std::string server_host, std::uint32_t server_port) override;
	};
}
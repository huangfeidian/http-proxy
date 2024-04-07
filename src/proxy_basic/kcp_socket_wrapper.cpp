#include "kcp_socket_wrapper.hpp"
#include "http_proxy_connection.hpp"

namespace http_proxy
{

	kcp_socket_wrapper::kcp_socket_wrapper(std::shared_ptr<asio::ip::udp::socket> in_socket)
		: socket_wrapper()
		, m_socket(std::move(in_socket))
		, m_last_recv_tick(clock())
	{
		m_send_buffer.reserve(4096 + MAX_HTTP_BUFFER_LENGTH);
		m_read_buffer.resize(4096 + MAX_HTTP_BUFFER_LENGTH);
	}

	kcp_client_socket_wrapper::kcp_client_socket_wrapper(std::shared_ptr<asio::ip::udp::socket> in_socket, const std::string& in_kcp_magic)
		: kcp_socket_wrapper(std::move(in_socket))
		, m_kcp_magic(in_kcp_magic)
		, m_resolver(m_socket->get_executor())
		, m_update_timer(m_socket->get_executor())
	{

	}


	void kcp_client_socket_wrapper::async_connect(std::string server_host, std::uint32_t server_port)
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

	void kcp_client_socket_wrapper::on_resolved(asio::ip::udp::resolver::iterator endpoint_iterator)
	{
		m_connection->connection_state = proxy_connection_state::connect_to_server;
		m_connection->set_timer(timer_type::connect);
		m_socket->async_connect(*endpoint_iterator, asio::bind_executor(m_connection->strand, [this, conn = m_connection->shared_from_this(), host = endpoint_iterator->host_name(), endpoint_iterator](const error_code& error) mutable
			{
				if (m_connection->cancel_timer(timer_type::connect))
				{
					if (!error)
					{
						m_remote_endpoint = *endpoint_iterator;
						on_udp_connected();
					}
					else
					{
						asio::error_code ec;
						m_socket->close(ec);
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

	void kcp_client_socket_wrapper::on_udp_connected()
	{
		m_connection->logger->info("{} on_udp_connected", m_connection->logger_prefix);
		m_kcp_handshake_data.push_back((char)kcp_packet_type::handshake);
		m_kcp_handshake_data.append(m_kcp_magic);
		m_socket->async_send(asio::buffer(m_kcp_handshake_data), asio::bind_executor(m_connection->strand, [this, conn = m_connection->shared_from_this()](asio::error_code ec, std::size_t bytes_transferred)
			{
				
				if (ec)
				{
					m_connection->logger->warn("{} fail to send handshake data to server with err {}", m_connection->logger_prefix, ec.message());
					m_connection->on_error(ec);
					return;
				}
				m_connection->logger->debug("{} suc to send  handshake data to server", m_connection->logger_prefix);
				m_kcp_handshake_data.clear();
				m_kcp_handshake_data.resize(sizeof(m_kcp_conn_index), 0);
				m_socket->async_receive(asio::buffer(m_kcp_handshake_data), asio::bind_executor(m_connection->strand, [this, conn](asio::error_code ec2, std::size_t bytes_transferred2)
					{
						if (ec2)
						{
							m_connection->logger->warn("{} fail to receive handshake data to server with error " , m_connection->logger_prefix, ec2.message());
							m_connection->on_error(ec2);
							return;
						}
						if (bytes_transferred2 != sizeof(m_kcp_conn_index))
						{
							assert(false);
						}
						
						std::memcpy(&m_kcp_conn_index, m_kcp_handshake_data.data(), sizeof(m_kcp_conn_index));
						m_connection->logger->debug("{} suc to get kcp conn index {}", m_connection->logger_prefix, m_kcp_conn_index);
						init_kcp_ctx();
						m_state = connection_state::opened;
						// todo
						m_connection->on_server_connected();
						start_kcp_update_timer();
					}));
			}));
		
	}

	void kcp_socket_wrapper::async_write_some(const asio::const_buffer& buffer, std::function<void(const asio::error_code&, std::size_t)>&& handler)
	{

		m_connection->logger->debug("{} async_write_some with data sz {}", m_connection->logger_prefix, buffer.size());
		// 如果已经在发送过程中 直接返回失败
		if (!m_kcp_ctx || m_send_cb )
		{
			asio::post(
				asio::bind_executor(m_socket->get_executor(), std::bind(std::move(handler), !is_open() ? asio::error::operation_aborted : asio::error::in_progress, 0)));
			return;
		}
		if (buffer.size() + 1>= m_send_buffer.capacity())
		{
			asio::post(
				asio::bind_executor(m_socket->get_executor(), std::bind(std::move(handler), asio::error::message_size, 0)));
			return;
		}
		m_send_buffer.resize(buffer.size() + 1);

		m_next_kcp_tick = 0;
		m_send_buffer[0] = std::uint8_t(kcp_packet_type::data);
		auto cur_data_begin = reinterpret_cast<const std::uint8_t*>(buffer.data());
		std::copy(cur_data_begin, cur_data_begin + buffer.size(), m_send_buffer.data() + 1);
		// 发送报错 直接返回发送的数据太大的错误码
		if (ikcp_send(m_kcp_ctx.get(), reinterpret_cast<const char*>(m_send_buffer.data()), buffer.size() + 1) < 0)
		{
			asio::post(
				asio::bind_executor(m_socket->get_executor(), std::bind(std::move(handler), asio::error::message_size, 0)));
			return;
		}
		// 发送窗口剩余包小于一定值 则认为已经发送 kcp会自己处理重传相关
		if (ikcp_waitsnd(m_kcp_ctx.get()) <= m_idle_send_packet_count)
		{

			asio::post(
				asio::bind_executor(m_socket->get_executor(), std::bind(std::move(handler), asio::error_code{}, 0)));
			return;
		}

		m_send_cb = std::move(handler);
		
	}

	void kcp_socket_wrapper::async_read_some(const asio::mutable_buffer& buffer, std::function<void(const asio::error_code&, std::size_t)>&& handler)
	{
		m_connection->get_logger()->debug("{} async_read_some with buffer sz {}", m_connection->logger_prefix, buffer.size());
		if (!m_kcp_ctx || m_read_cb || !is_open())
		{
			asio::post(
				asio::bind_executor(m_socket->get_executor(), std::bind(std::move(handler), !is_open() ? asio::error::operation_aborted : asio::error::in_progress, 0)));
			return;
		}

		m_read_dest = buffer;
		m_read_cb = std::move(handler);

		async_read_some_impl();
	}

	void kcp_client_socket_wrapper::async_read_some_impl()
	{
		m_socket->async_receive(m_read_dest, [this](const asio::error_code& ec, std::size_t read_sz)
			{
				if (ec)
				{
					auto temp_read_cb = std::move(m_read_cb);
					temp_read_cb(ec, 0);
					return;
				}
				on_receive(read_sz, clock());
			});
	}

	bool kcp_socket_wrapper::is_open() const
	{
		return m_state == connection_state::opened;
	}
	void kcp_client_socket_wrapper::shutdown()
	{
		if (!m_socket->is_open())
		{
			return;
		}
		close(asio::error::make_error_code(asio::error::operation_aborted));

	}

	kcp_socket_wrapper::~kcp_socket_wrapper()
	{
		
	}

	void kcp_socket_wrapper::init_kcp_ctx()
	{
		m_kcp_ctx = std::unique_ptr<ikcpcb, kcp_obj_deleter>{ ikcp_create(m_kcp_conn_index, this) };
		ikcp_wndsize(m_kcp_ctx.get(), 256, 256);
		ikcp_nodelay(m_kcp_ctx.get(), 1, 10, 2, 1);
		ikcp_setmtu(m_kcp_ctx.get(), 1200);
		m_kcp_ctx->rx_minrto = 10;
		m_kcp_ctx->stream = 1;
		// 这里绑定真正的发送函数
		ikcp_setoutput(m_kcp_ctx.get(), [](const char* buf, int len, ikcpcb*, void* user) {
			kcp_socket_wrapper* conn = (kcp_socket_wrapper*)user;
			conn->async_write_some_impl(buf, 0, len);
			return 0;
			});
	}

	void kcp_client_socket_wrapper::async_write_some_impl(const char* buf, std::uint32_t offset, std::uint32_t remain_sz)
	{
		m_socket->async_send_to(asio::buffer(buf + offset, remain_sz), m_remote_endpoint, [this, conn = m_connection->shared_from_this()](const std::error_code&, size_t)
			{
				// udp的发送不会有失败 而且是整包发送
				check_write_finish();
			});
	}


	void kcp_socket_wrapper::check_read_finish()
	{
		if (m_read_cb)
		{
			int n = ikcp_recv(m_kcp_ctx.get(), reinterpret_cast<char*>(m_read_dest.data()), m_read_dest.size());
			if (n > 0)
			{
				// 读取到了一个packet
				auto temp_read_cb = std::move(m_read_cb);
				temp_read_cb(asio::error_code{}, n);
			}
		}
	}

	void kcp_socket_wrapper::check_write_finish()
	{
		if (m_send_cb)
		{
			// 任何时候剩余发送窗口数量小于一定值都认为发送成功
			if (ikcp_waitsnd(m_kcp_ctx.get()) <= m_idle_send_packet_count)
			{
				auto temp_cb = std::move(m_send_cb);
				temp_cb(asio::error_code{}, 0);
			}
		}
	}

	void kcp_socket_wrapper::on_receive(std::uint64_t packet_sz, time_t t)
	{

		if (m_state == connection_state::idle)
		{
			m_state = connection_state::opened;
		}
		m_last_recv_tick = t;
		std::uint8_t opcode = static_cast<std::uint8_t>(m_read_buffer[0]);
		m_connection->get_logger()->debug("{} on_receive with packet_sz {} op_code {}", m_connection->logger_prefix, packet_sz, opcode);
		switch (opcode)
		{
			case std::uint8_t(kcp_packet_type::disconnect) :
			{
				if (nullptr != m_kcp_ctx)
				{
					close(asio::error::make_error_code(asio::error::eof));
				}
				return;
			}
			case std::uint8_t(kcp_packet_type::keepalive) :
			{
				return;
			}
			case std::uint8_t(kcp_packet_type::data):
			{
				if (nullptr == m_kcp_ctx)
				{
					init_kcp_ctx();
				}
				ikcp_input(m_kcp_ctx.get(), m_read_buffer.data() + 1, packet_sz - 1);
				m_next_kcp_tick = 0;
				
				check_read_finish();
				check_write_finish();
			}
			default:
				break;
		}
	}
	time_t kcp_socket_wrapper::do_update(time_t now)
	{
		if (m_kcp_ctx && m_next_kcp_tick <= now)
		{
			ikcp_update(m_kcp_ctx.get(), now);
			m_next_kcp_tick = ikcp_check(m_kcp_ctx.get(), now);
			if (m_next_kcp_tick - now < m_update_interval)
			{
				ikcp_flush(m_kcp_ctx.get());
			}
		}
		return m_last_recv_tick;
	}

	void kcp_socket_wrapper::close(const asio::error_code& ec)
	{
		if (m_state == connection_state::closed)
		{
			return;
		}

		if (ec == asio::error::timed_out)
		{
			m_connection->logger->error("{} timeout ", m_connection->logger_prefix);
		}
		m_state = connection_state::closed;
		close_impl();

	}

	void kcp_client_socket_wrapper::close_impl()
	{
		ikcp_flush(m_kcp_ctx.get());
		auto temp_conn = m_connection->shared_from_this();
		m_socket->cancel();
		std::string temp_str;
		temp_str.push_back(std::uint8_t(kcp_packet_type::disconnect));

		
		m_socket->send_to(asio::buffer(temp_str), m_remote_endpoint);
		asio::error_code ignore;
		m_socket->close(ignore);
		m_update_timer.cancel();
	}

	void kcp_client_socket_wrapper::start_kcp_update_timer()
	{
		m_update_timer.expires_after(std::chrono::milliseconds(m_update_interval));
		m_update_timer.async_wait([this, conn = m_connection->shared_from_this()](const asio::error_code& ec)
			{
				if (ec)
				{
					return;
				}
				time_t now = clock();
				time_t t = do_update(now);
				if ((now - t) > m_timeout_duration)
				{
					close(asio::error::timed_out);
					return;
				}
				start_kcp_update_timer();
			});
	}

	kcp_acceptor::kcp_acceptor(asio::io_context& in_ioc, asio::ip::udp::endpoint in_listen_endpoint, std::shared_ptr<spdlog::logger> in_logger, const std::string& in_magic)
		: m_ioc(in_ioc)
		, m_update_timer(m_ioc)
		, m_listen_endpoint(in_listen_endpoint)
		, m_socket(std::make_shared<asio::ip::udp::socket>(m_ioc.get_executor(), in_listen_endpoint))
		, m_logger(in_logger)
		, m_magic(in_magic)
		, m_now(clock())
	{
		m_read_buffer.resize(4096 + MAX_HTTP_BUFFER_LENGTH);
		do_receive();
		update();
	}
	void kcp_acceptor::do_receive()
	{
		m_socket->async_receive_from(asio::buffer(m_read_buffer), m_read_from_endpoint, [this](const std::error_code& ec, size_t size)
			{
				if (ec)
				{
					m_logger->error("async_receive_from fail with ec {}", ec.message());
					do_receive();
					return;
				}
				
				do
				{
					if (size == 0)
					{
						break;
					}
					std::uint8_t packet_type = m_read_buffer[0];
					m_logger->debug("kcp_acceptor::do_receive remote {} port {} packet_type {} data_sz {}", m_read_from_endpoint.address().to_string(), m_read_from_endpoint.port(), packet_type, size);
					if (packet_type >= std::uint8_t(kcp_packet_type::max))
					{
						m_logger->error("async_receive_from with packet_type {}", packet_type);
						break;
					}
					if (packet_type == std::uint8_t(kcp_packet_type::handshake))
					{
						if (size - 1 != m_magic.size() || m_magic != std::string(m_read_buffer.data() + 1, size - 1))
						{
							m_logger->error("async_receive_from handshake fail sz {}", size);
							break;
						}
						if (!m_accept_cb)
						{
							m_logger->error("async_receive_from handshake fail accept cb empty");
							break;
						}
						std::shared_ptr<kcp_server_socket_wrapper> temp_conn;
						auto temp_iter = m_client_connections.find(m_read_from_endpoint);
						if (temp_iter != m_client_connections.end())
						{
							temp_conn = temp_iter->second;
							if (temp_conn->get_state() != connection_state::idle)
							{
								temp_conn->close(asio::error::make_error_code(asio::error::operation_aborted));
								temp_conn.reset();
								m_client_connections.erase(temp_iter);
							}
						}
						if (!temp_conn)
						{
							temp_conn = std::make_shared<kcp_server_socket_wrapper>(m_socket, *this, m_read_from_endpoint, make_conn_idx());
							m_logger->info("create new kcp conn {}", temp_conn->get_conn_idx());
							m_client_connections[m_read_from_endpoint] = temp_conn;
							std::shared_ptr<std::string> response = std::make_shared<std::string>();
							uint32_t conv = temp_conn->get_conn_idx();
							response->append(reinterpret_cast<const char*>(&conv), sizeof(conv));

							auto b = asio::buffer(response->data(), response->size());
							m_socket->async_send_to(b, m_read_from_endpoint, [response = std::move(response), temp_conn, this](std::error_code, size_t)
								{
									m_logger->info("send new kcp conn {} to client ", temp_conn->get_conn_idx());
									temp_conn->start();
									
									auto temp_cb = std::move(m_accept_cb);
									temp_cb(temp_conn);
								});
							
						}

						
					}
					else
					{
						auto temp_iter = m_client_connections.find(m_read_from_endpoint);
						if (temp_iter != m_client_connections.end())
						{
							temp_iter->second->on_receive(m_read_buffer.data(), size, m_now);
						}
						else
						{
							m_logger->error("fail to find connection for endpoint {}", m_read_from_endpoint.address().to_string());
						}
					}
				} while (0);
				do_receive();
			});
	}

	void kcp_server_socket_wrapper::on_receive(const char* data, std::uint64_t size, time_t ts)
	{
		std::lock_guard<std::mutex> temp_lock(m_logic_mutex);
		
		std::copy(data, data + size, m_read_buffer.data());
		kcp_socket_wrapper::on_receive(size, ts);
	}
	void kcp_acceptor::update()
	{
		m_update_timer.expires_after(std::chrono::microseconds(update_gap));
		m_update_timer.async_wait([this](const asio::error_code& e)
			{
				if (e)
				{
					return;
				}
				m_now = clock();
				for (auto iter = m_client_connections.begin(); iter != m_client_connections.end();)
				{
					auto last_recv_time = iter->second->update(m_now);
					if (iter->second->get_state() == connection_state::closed || (m_now - last_recv_time) > timeout_duration)
					{
						iter->second->close(!iter->second->is_open() ? asio::error::operation_aborted : asio::error::timed_out);
						m_used_conn_idxes.erase(iter->second->get_conn_idx());
						iter = m_client_connections.erase(iter);
					}
					else
					{
						iter++;
					}
				}
				update();
			});
	}

	std::uint32_t kcp_acceptor::make_conn_idx()
	{
		while (!m_used_conn_idxes.emplace(++m_conn_counter).second) {};
		return m_conn_counter;
	}

	void kcp_acceptor::async_accept(std::function<void(std::shared_ptr< kcp_server_socket_wrapper>)> accept_cb)
	{
		m_accept_cb = accept_cb;
	}

	void kcp_acceptor::do_send(asio::ip::udp::endpoint send_to_endpoint, std::string_view data)
	{
		std::lock_guard<std::mutex> temp_lock(m_send_queue_lock);
		m_send_queues.push(std::make_pair(send_to_endpoint, std::make_shared<std::string>(data.data(),data.size())));
		if (m_send_queues.size() == 1)
		{
			auto cur_front = m_send_queues.front();
			m_socket->async_send_to(asio::buffer(*cur_front.second), cur_front.first, [this](const std::error_code&, size_t)
				{
					after_send();
				});
		}
	}

	void kcp_acceptor::after_send()
	{
		std::lock_guard<std::mutex> temp_lock(m_send_queue_lock);
		if (m_send_queues.empty())
		{
			return;
		}
		
		auto cur_front_endpoint = m_send_queues.front().first;
		auto temp_iter = m_client_connections.find(cur_front_endpoint);
		if (temp_iter != m_client_connections.end())
		{
			m_logger->debug("kcp_acceptor::after_send remote {} data sz {} conn_idx {}", cur_front_endpoint.address().to_string(), m_send_queues.front().second->size(), temp_iter->second->get_conn_idx());
			temp_iter->second->check_write_finish();
		}
		m_send_queues.pop();
		if (m_send_queues.empty())
		{
			return;
		}
		auto cur_front = m_send_queues.front();
		m_socket->async_send_to(asio::buffer(*cur_front.second), cur_front.first, [this](const std::error_code&, size_t)
			{
				after_send();
			});
	}

	time_t kcp_server_socket_wrapper::update(time_t now_ts)
	{
		std::lock_guard<std::mutex> temp_lock(m_logic_mutex);
		return do_update(now_ts);
	}

	void kcp_server_socket_wrapper::async_read_some_impl()
	{
		


	}

	kcp_server_socket_wrapper::kcp_server_socket_wrapper(std::shared_ptr<asio::ip::udp::socket> in_socket, kcp_acceptor& in_acceptor, asio::ip::udp::endpoint in_remote_endpoint, std::uint32_t in_conn_idx)
		: kcp_socket_wrapper(in_socket)
		, m_acceptor(in_acceptor)
	{
		m_remote_endpoint = in_remote_endpoint;
		m_kcp_conn_index = in_conn_idx;
	}

	void kcp_server_socket_wrapper::async_write_some_impl(const char* buf, std::uint32_t offset, std::uint32_t remain_sz)
	{
		m_acceptor.do_send(m_remote_endpoint, std::string_view(buf + offset, remain_sz));
	}

	void kcp_server_socket_wrapper::close_impl()
	{
		ikcp_flush(m_kcp_ctx.get());
		auto temp_conn = m_connection->shared_from_this();
		std::string temp_buffer;
		temp_buffer.push_back(std::uint8_t(kcp_packet_type::disconnect));
		m_acceptor.do_send(m_remote_endpoint, temp_buffer);

	}

	void kcp_acceptor::close()
	{
		
		asio::error_code ignore;
		m_update_timer.cancel(ignore);
		m_socket->cancel(ignore);
		m_socket->close();
	}

	void kcp_server_socket_wrapper::shutdown()
	{
		close(asio::error::make_error_code(asio::error::operation_aborted));
	}

	void kcp_server_socket_wrapper::async_connect(std::string server_host, std::uint32_t server_port)
	{
		exit(1);
	}

	kcp_server_socket_wrapper::~kcp_server_socket_wrapper()
	{
		shutdown();
	}

	void kcp_server_socket_wrapper::start()
	{
		m_state = connection_state::opened;
		init_kcp_ctx();
	}
}
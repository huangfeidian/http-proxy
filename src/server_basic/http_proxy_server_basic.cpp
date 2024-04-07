

#include <iostream>
#include <memory>
#include <thread>
#include <vector>



#include "http_proxy_server_basic.hpp"
#include "http_proxy_server_config.hpp"
#include "http_proxy_server_connection.hpp"
#include "tcp_socket_wrapper.hpp"
#include "kcp_socket_wrapper.hpp"

#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

namespace http_proxy {

using std::cerr;
http_proxy_server_basic::http_proxy_server_basic(asio::io_context& io_context) :
	io_context(io_context),
	m_tcp_acceptor(io_context)
	
{}

void http_proxy_server_basic::run()
{
	const auto& config = http_proxy_server_config::get_instance();
	const auto& kcp_mgaic = config.get_kcp_magic();
	

	
	auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
	console_sink->set_level(config.get_console_log_level());
	auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(config.get_log_file_name(), true);
	file_sink->set_level(config.get_file_log_level());
	this->logger = std::make_shared<spdlog::logger>(std::string("ahps_basic"), spdlog::sinks_init_list{ console_sink, file_sink });
	this->logger->set_level(config.get_log_level());
	spdlog::flush_every(std::chrono::seconds(1));
	if (kcp_mgaic.empty())
	{
		asio::ip::tcp::endpoint endpoint(asio::ip::address::from_string(config.get_bind_address()), config.get_listen_port());
		this->m_tcp_acceptor.open(endpoint.protocol());
		this->m_tcp_acceptor.bind(endpoint);
		this->m_tcp_acceptor.listen(asio::socket_base::max_connections);
	}
	else
	{
		asio::ip::udp::endpoint endpoint(asio::ip::address::from_string(config.get_bind_address()), config.get_listen_port());

		m_kcp_acceptor = std::make_shared<kcp_acceptor>(io_context, endpoint, logger,  kcp_mgaic);
		logger->info("bind udp on {} {}", config.get_bind_address(), config.get_listen_port());
	}
	this->start_accept();
	std::vector<std::thread> td_vec;

	for (auto i = 0; i < config.get_workers(); ++i) {
		td_vec.emplace_back([this]() {
			try {
				this->io_context.run();
			}
			catch (const std::exception& e) {
				std::cerr << e.what() << std::endl;
			}
		});
	}

	for (auto& td : td_vec) {
		td.join();
	}
}

void http_proxy_server_basic::start_accept()
{
	if (m_kcp_acceptor)
	{
		m_kcp_acceptor->async_accept([this](std::shared_ptr<kcp_server_socket_wrapper> kcp_socket)
			{
				if (kcp_socket)
				{
					logger->info("new kcp conn with index {}", kcp_socket->get_conn_idx());

					auto other_socket = std::make_shared<tcp_socket_wrapper>(asio::ip::tcp::socket(this->m_tcp_acceptor.get_executor()));
					auto connection = http_proxy_server_connection::create(io_context, kcp_socket, std::move(other_socket), logger, http_proxy_server_config::get_instance().increase_connection_count());
					logger->info("new kcp conn with index {} connection_counter {}", kcp_socket->get_conn_idx(), connection->connection_count);
					connection->start();
				}

				this->start_accept();
			});
	}
	else
	{
		auto socket = std::make_shared<tcp_socket_wrapper>(asio::ip::tcp::socket(this->m_tcp_acceptor.get_executor()));
		this->m_tcp_acceptor.async_accept(socket->get_socket(), [socket, this](const error_code& error) {
			if (!error) {
				auto other_socket = std::make_shared<tcp_socket_wrapper>(asio::ip::tcp::socket(this->m_tcp_acceptor.get_executor()));
				auto connection = http_proxy_server_connection::create(io_context, socket, std::move(other_socket), logger, http_proxy_server_config::get_instance().increase_connection_count());

				connection->start();
				this->start_accept();
			}
			});
	}
	
}

} //namespace http_proxy

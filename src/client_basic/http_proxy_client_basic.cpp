

#include <iostream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "http_proxy_client_basic.hpp"
#include "http_proxy_client_connection.hpp"
#include "http_proxy_client_config.hpp"

#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include "tcp_socket_wrapper.hpp"
#include "kcp_socket_wrapper.hpp"

namespace http_proxy
{
	using std::cerr;
	using namespace std;
	http_proxy_client_basic::http_proxy_client_basic(asio::io_context& io_context) :
		io_context(io_context),
		acceptor(io_context)


	{
	}

	void http_proxy_client_basic::run()
	{
		const auto& config = http_proxy_client_config::get_instance();
		asio::ip::tcp::endpoint endpoint(asio::ip::address::from_string(config.get_bind_address()), config.get_listen_port());
		this->acceptor.open(endpoint.protocol());
		this->acceptor.bind(endpoint);
		this->acceptor.listen(asio::socket_base::max_connections);
		
		auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
		console_sink->set_level(config.get_console_log_level());
		auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(config.get_log_file_name(), true);
		file_sink->set_level(config.get_file_log_level());
		this->logger = std::make_shared<spdlog::logger>("ahpc_basic", spdlog::sinks_init_list{ console_sink, file_sink });
		this->logger->set_level(config.get_log_level());
		this->logger->flush_on(spdlog::level::warn);
		spdlog::flush_every(std::chrono::seconds(1));
		this->logger->info("http_proxy_client runs with {} threads", config.get_workers());
		this->start_accept();
		std::vector<std::thread> td_vec;
		for (auto i = 0; i < config.get_workers(); ++i)
		{
			td_vec.emplace_back([this]()
			{
				try
				{
					this->io_context.run();
				}
				catch (const std::exception& e)
				{
					std::cerr << e.what() << std::endl;
				}
			});
		}

		for (auto& td : td_vec)
		{
			td.join();
		}
	}

	void http_proxy_client_basic::start_accept()
	{
		auto socket = std::make_shared<tcp_socket_wrapper>(asio::ip::tcp::socket(this->acceptor.get_executor()));
		this->acceptor.async_accept(socket->get_socket(), [socket, this](const error_code& error)
		{
			if (!error)
			{
				std::shared_ptr<socket_wrapper> other_socket;
				auto cur_kcp_magic = http_proxy_client_config::get_instance().get_kcp_magic();
				if (!cur_kcp_magic.empty())
				{
					other_socket = std::make_shared<kcp_client_socket_wrapper>(std::make_shared<asio::ip::udp::socket>(this->acceptor.get_executor()), cur_kcp_magic);
				}
				else
				{
					other_socket = std::make_shared<tcp_socket_wrapper>(asio::ip::tcp::socket(this->acceptor.get_executor()));
				}
				
				auto connection = http_proxy_client_connection::create(io_context, socket, other_socket, this->logger, http_proxy_client_config::get_instance().increase_connection_count());
				connection->start();
				this->start_accept();
			}
		});
	}

} // namespace http_proxy

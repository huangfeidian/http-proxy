

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
		auto socket = std::make_shared<asio::ip::tcp::socket>(this->acceptor.get_executor());
		this->acceptor.async_accept(*socket, [socket, this](const error_code& error)
		{
			if (!error)
			{
				this->start_accept();

				auto connection = http_proxy_client_connection::create(std::move(*socket), std::move(asio::ip::tcp::socket(this->acceptor.get_executor())), this->logger, http_proxy_client_config::get_instance().increase_connection_count());

				connection->start();
			}
		});
	}

} // namespace http_proxy

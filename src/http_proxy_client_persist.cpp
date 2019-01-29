

#include <iostream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "http_proxy_client_persist.hpp"
#include "http_proxy_client_session.hpp"
#include "http_proxy_client_config.hpp"

#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

namespace azure_proxy
{
	using std::cerr;
	using namespace std;
	http_proxy_client_persist::http_proxy_client_persist(asio::io_service& io_service) :
		io_service(io_service),
		acceptor(io_service)


	{
	}

	void http_proxy_client_persist::run()
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
		this->logger = std::make_shared<spdlog::logger>("ahpc_persist", spdlog::sinks_init_list{ console_sink, file_sink });
		this->logger->set_level(config.get_log_level());
		this->logger->info("http_proxy_client_persist runs with {} threads", config.get_workers());
		connection_count = 0;
		this->start_accept();
		std::vector<std::thread> td_vec;
		for (auto i = 0; i < config.get_workers(); ++i)
		{
			td_vec.emplace_back([this]()
			{
				try
				{
					this->io_service.run();
				}
				catch (const std::exception& e)
				{
					std::cerr << e.what() << std::endl;
				}
			});
		}
        for (auto i = 0; i < config.get_workers(); ++i)
        {
            auto one_session_manager = http_proxy_client_session_manager::create(io_service, logger, connection_count++);
            _session_managers.push_back(one_session_manager);
            one_session_manager->start();

        }
		for (auto& td : td_vec)
		{
			td.join();
		}
        _session_managers.clear();
	}

	void http_proxy_client_persist::start_accept()
	{
		auto socket = std::make_shared<asio::ip::tcp::socket>(this->acceptor.get_io_service());
		this->acceptor.async_accept(*socket, [socket, this](const error_code& error)
		{
			if (!error)
			{
				this->start_accept();
                auto cur_connection_count = connection_count++;
                auto cur_session = http_proxy_client_session::create(std::move(socket), std::move(asio::ip::tcp::socket(this->acceptor.get_io_service())), logger, cur_connection_count++, *_session_managers[cur_connection_count % _session_managers.size()]);
				cur_session->start();
			}
		});
	}

} // namespace azure_proxy

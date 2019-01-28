#include "http_proxy_connection.hpp"

namespace azure_proxy
{
    http_proxy_connection::http_proxy_connection(asio::ip::tcp::socket&& in_client_socket, asio::ip::tcp::socket&& in_server_socket, std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_idx, std::uint32_t in_timeout)
    :
    strand(in_client_socket.get_io_service()),
    client_socket(std::move(in_client_socket)),
    server_socket(std::move(in_server_socket)),
    resolver(this->client_socket.get_io_service()),
    connection_state(proxy_connection_state::ready),
    timer(this->client_socket.get_io_service()),
    timeout(std::chrono::seconds(in_timeout)),
    logger(in_logger),
    connection_count(in_connection_count),
    logger_prefix("connection " +std::to_string(connection_count) + ": ")
    {

    }
    static std::shared_ptr<http_proxy_connection> http_proxy_connection::create(asio::ip::tcp::socket&& _in_client_socket, asio::ip::tcp::socket&& _in_server_socket, std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_idx, std::uint32_t _in_timeout)
    {
        return std::make_shared<http_proxy_connection>(std::move(_in_client_socket), std::move(_in_server_socket), logger, in_connection_idx, _in_timeout);
    }

    void http_proxy_connection::report_error(http_parser_result _status)
    {
        auto error_detail = from_praser_result_to_description(_status);
        report_error(std::to_string(std::get<0>(error_detail)), std::get<1>(error_detail), std::get<2>(error_detail));
    }
    void http_proxy_connection::close_connection()
    {
        error_code ec;
        if (this->server_socket.is_open())
        {
            this->server_socket.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
            this->server_socket.close(ec);
        }
        if (this->client_socket.is_open())
        {
            this->client_socket.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
            this->client_socket.close(ec);
        }
    }
    void http_proxy_connection::report_error(const std::string& status_code, const std::string& status_description, const std::string& error_message)
    {
        logger->warn("{} report error status_code {} status_description {} error_message {}", logger_prefix, status_code, status_description, error_message);
		close_connection();
    }
    void http_proxy_connection::on_timeout()
	{
		
		if (this->connection_state == proxy_connection_state::resolve_proxy_server_address)
		{
			this->resolver.cancel();
		}
		else
		{
			logger->warn("{} on_timeout shutdown connection", logger_prefix);
			close_connection();
		}
	}
    void http_proxy_connection::on_error(const error_code& error)
	{
		logger->warn("{} error shutdown connection {}", logger_prefix, error.message());
		this->cancel_timer();
		close_connection();
	}
    bool http_proxy_connection::cancel_timer()
	{
		std::size_t ret = this->timer.cancel();
		assert(ret <= 1);
		return ret == 1;
	}
    void http_proxy_connection::set_timer()
	{
		if (this->timer.expires_from_now(this->timeout) != 0)
		{
			assert(false);
		}
		auto self(this->shared_from_this());
		this->timer.async_wait(this->strand.wrap([this, self](const error_code& error)
		{
			if (error != asio::error::operation_aborted)
			{
				this->on_timeout();
			}
		}));
	}
    void http_proxy_connection::async_connect_to_server(std::string server_ip, std::uint32_t server_port)
    {
        auto self(this->shared_from_this());
		asio::ip::tcp::resolver::query query(server_ip, std::to_string(server_port));
		this->connection_state = proxy_connection_state::resolve_proxy_server_address;
		this->set_timer();
		this->resolver.async_resolve(query, [this, self, =](const error_code& error, asio::ip::tcp::resolver::iterator iterator)
		{
			if (this->cancel_timer())
			{
				if (!error)
				{
					this->connection_state = proxy_connection_state::connecte_to_proxy_server;
					this->set_timer();
					this->server_socket.async_connect(*iterator, this->strand.wrap([this, self](const error_code& error)
					{
						if (this->cancel_timer())
						{
							if (!error)
							{
								this->on_server_connected();
							}
							else
							{
								logger->warn("{} fail to connect to server {} port {}", logger_prefix, server_ip, server_port);
								this->on_error(error);
							}
						}
					}));
				}
				else
				{
					logger->warn("{} fail to resolve server {}", logger_prefix, server_ip);
					this->on_error(error);
				}
			}
		});
    }
}
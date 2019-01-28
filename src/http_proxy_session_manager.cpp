#include "http_proxy_session_manager.hpp"

namespace azure_proxy
{
    http_proxy_session_manager::http_proxy_session_manager(asio::io_service& _in_io_service, std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count, std::uint32_t _in_timeout, bool _in_is_downgoing):
	http_proxy_connection(std::move(asio::ip::tcp::socket(_in_io_service)), std::move(asio::ip::tcp::socket(_in_io_service)), logger, in_connection_count, _in_timeout),
	is_downgoing(_in_is_downgoing)

	{

	}
	static std::shared_ptr<http_proxy_session_manager> http_proxy_session_manager::create(asio::io_service& _in_io_service, std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count, std::uint32_t _in_timeout, bool _in_is_downgoing)
	{
		return std::make_shared<http_proxy_session_manager>(_in_io_service, logger, in_connection_count, _in_timeout, _in_is_downgoing);
	}
	bool http_proxy_session_manager::post_send_task(std::uint32_t session_idx, const unsigned char* send_buffer, std::uint32_t buffer_size)
	{
		return post_send_task(session_idx, send_buffer, buffer_size, session_data_cmd::session_data);
	}
	bool http_proxy_session_manager::post_send_task(std::uint32_t session_idx, const unsigned char* send_buffer, std::uint32_t buffer_size, session_data_cmd data_type)
	{
		send_task_desc cur_task{session_idx, buffer_size, send_buffer, data_type};
		std::unique_lock<std::mutex> queue_lock(_send_task_mutex);
		queue_lock.lock()
		bool send_in_progress = !send_task_queue.empty();
		send_task_queue.push(cut_task);
		queue_lock.unlock()
		if(!send_in_progress)
		{
			do_send_one();
		}
		return send_in_progress;
	}
	bool http_proxy_session_manager::post_read_task(std::shared_ptr<http_proxy_connection> _task_session, unsigned char* read_buffer, std::uint32_t min_read_size, std::uint32_t max_read_size)
	{
		read_task_desc cur_task{_task_session->connection_count, min_read_size, max_read_size, read_buffer, 0};
		std::lock_guard<std::mutex> lock(_task_mutex);
		_read_tasks[_task_session->connection_count] = cur_task;
	}
	void do_send_one()
	{
		auto cur_task = send_task_queue.front();
		std::uint32_t send_size = 0;
		char* buffer_begin = server_send_buffer.data();
		if(is_downgoing)
		{
			buffer_begin = client_send_buffer.data();
		}
		send_size = cur_task.buffer_size;
		network_utils::encode_network_int(buffer_begin, send_size);
		network_utils::encode_network_int(buffer_begin + 4, cur_task.data_type);
		network_utils::encode_network_int(buffer_begin + 8, cur_task.session_idx);
		if(buffer_size)
		{
			std::copy(cur_task.buffer, cur_task.buffer + cur_task.buffer_size, buffer_begin + 12);
			if(encryptor)
			{
				encryptor->transform(std::reinterpret_cast<unsigned char *>(buffer_begin + 12), send_size, 128);
			}
		}
		
		if(is_downgoing)
		{
			async_write_data_to_client(0, send_size + 12);
		}
		else
		{
			async_send_data_to_server(0, send_size + 12);
		}
	}
	void http_proxy_session_manager::on_client_data_send(std::uint32_t bytes_transfer)
	{
		bool remain_progress = false;
		{
			std::lock_guard<std::mutex> queue_lock(_send_task_mutex);
			send_task_queue.pop_front();
			remain_progress = !send_task_queue.empty();
		}
		if(remain_progress)
		{
			do_send_one();
		}
	}
	void http_proxy_session_manager::on_server_data_send(std::uint32_t bytes_transfer)
	{
		bool remain_progress = false;
		{
			std::lock_guard<std::mutex> queue_lock(_send_task_mutex);
			send_task_queue.pop_front();
			remain_progress = !send_task_queue.empty();
		}
		if(remain_progress)
		{
			do_send_one();
		}
	}
	void add_session(std::shared_ptr<http_proxy_connection>&& _new_session)
	{
		std::uint32_t session_count = _new_session->connection_count;
		{
			std::lock_guard<std::mutex> session_guard(_session_mutex);
			_sessions[_new_session->connection_count] = std::move(_new_session);
		}
		post_send_task(session_count, std::nullptr, 0, session_data_cmd::new_session)
		
	}
	void remove_session(std::uint32_t _session_idx)
	{
		{
			std::lock_guard<std::mutex> session_guard(_session_mutex);
			_sessions.erase(_session_idx);
		}
		post_send_task(_new_session->connection_count, std::nullptr, 0, session_data_cmd::remove_session)
	}
	void http_proxy_session_manager::on_data_arrived(std::uint32_t byte_transfered, const char* read_buffer)
	{
		bytes_transfer += buffer_offset - read_offset;
		buffer_offset += bytes_transfer;
		while(true)
		{
			std::uint32_t offset = 0;
			auto cur_parse_result = parse_data(read_buffer, bytes_transfer, read_offset);
			if(!cur_parse_result.first)
			{
				if(is_downgoing)
				{
					async_read_data_from_client(true, cur_parse_result.second, BUFFER_LENGTH);
				}
				else
				{
					async_read_data_from_server(true, cur_parse_result.second, BUFFER_LENGTH);
				}
				
				return;
			}
			std::uint32_t data_type = network_utils::decode_network_int(read_buffer + read_offset + 4);
			std::uint32_t session_idx = network_utils::decode_network_int(read_buffer + read_offset + 8);

			if(decryptor)
			{
				decryptor->decrypt(read_buffer + read_offset + 12, _decrypt_buffer.data(), cur_parse_result.second);
			}
			else
			{
				std::copy(read_buffer + read_offset + 12, server_read_buffer.data() + read_offset + 12 + cur_parse_result.second, _decrypt_buffer.data());
			}
			read_offset += 12 + cur_parse_result.second;
			std::shared_ptr<http_proxy_connection> _cur_session;
			{
				std::lock_guard<std::mutex> _session_guard;
				auto cur_iter = _sessions.find(session_idx);
				if(cur_iter)
				{
					_cur-session = cur_iter->second;
				}
			}
			if(!_cur_session)
			{
				continue;
			}
			std::uint32_t min_read_size = 1;
			std::uint32_t already_read_size = 0;
			std::uint32_t max_read_size = BUFFER_LENGTH;
			char* session_read_buffer = nullptr;
			{
				std::lock_guard<std::mutex> _session_guard;
				auto cur_iter = _read_tasks.find(session_idx);
				if(cur_iter)
				{
					min_read_size = cur_iter->second.min_read_size;
					already_read_size = cur_iter->second.already_read_size;
					cur_iter->second.already_read_size += cur_parse_result.second;
					max_read_size = cur_iter->second.max_read_size;
					session_read_buffer = cur_iter->second.buffer;
				}
			}
			if(!session_read_buffer)
			{
				continue;
			}
			std::copy(_decrypt_buffer.data(), _decrypt_buffer.data() + cur_parse_result.second, session_read_buffer + already_read_size);
			already_read_size += cur_parse_result.second
			if(already_read_size >= min_read_size)
			{
				if(is_downgoing)
				{
					_cur_session->on_client_data_arrived(already_read_size);
				}
				else
				{
					_cur_session->on_server_data_arrived(already_read_size);
				}
				
			}
		}
	}
	void http_proxy_session_manager::on_server_data_arrived(std::uint32_t bytes_transfer)
	{
		on_data_arrived(bytes_transfer, server_read_buffer.data());
	}
	void http_proxy_session_manager::on_client_data_arrived(std::uint32_t bytes_transfer)
	{
		on_data_arrived(bytes_transfer, client_read_buffer.data());
	}
	void http_proxy_session_manager::async_read_data_from_server(bool set_timer, std::uint32_t at_least_size, std::uint32_t at_most_size)
	{
		logger->debug("{} async_read_data_from_server begin", logger_prefix);
		if(read_offset > BUFFER_LENGTH)
		{
			std::copy(server_read_buffer.data() + read_offset, server_read_buffer.data() + buffer_offset, server_read_buffer.data());
			buffer_offset -= read_offset;
			read_offset = 0;
		}
		auto self(this->shared_from_this());
		if (set_timer)
		{
			this->set_timer();
		}
		
		asio::async_read(this->server_socket,
			asio::buffer(server_read_buffer.data() + buffer_offset, at_most_size),
			asio::transfer_at_least(at_least_size),
			this->strand.wrap([this, self](const error_code& error, std::size_t bytes_transferred)
		{
			if (this->cancel_timer())
			{
				if (!error)
				{
					this->on_server_data_arrived(bytes_transferred);
				}
				else
				{
					this->on_error(error);
				}
			}
		})
		);
	}
	void http_proxy_session_manager::async_read_data_from_client(bool set_timer, std::uint32_t at_least_size, std::uint32_t at_most_size)
	{
		logger->debug("{} async_read_data_from_server begin", logger_prefix);
		if(read_offset > BUFFER_LENGTH)
		{
			std::copy(client_read_buffer.data() + read_offset, client_read_buffer.data() + buffer_offset, client_read_buffer.data());
			buffer_offset -= read_offset;
			read_offset = 0;
		}
		auto self(this->shared_from_this());
		if (set_timer)
		{
			this->set_timer();
		}
		
		asio::async_read(this->client_socket,
			asio::buffer(client_read_buffer.data() + buffer_offset, at_most_size),
			asio::transfer_at_least(at_least_size),
			this->strand.wrap([this, self](const error_code& error, std::size_t bytes_transferred)
		{
			if (this->cancel_timer())
			{
				if (!error)
				{
					this->on_client_data_arrived(bytes_transferred);
				}
				else
				{
					this->on_error(error);
				}
			}
		})
		);
	}

	std::pair<bool, std::uint32_t> http_proxy_session_manager::parse_data(const char* buffer, std::uint32_t buffer_size, std::uint32_t offset)
	// bool: get one complete packet
	// uint32_t if bool is true represent the packet size else at least more size to read
	{
		if(buffer_size - offset < 12)
		{
			return std::make_pair(false, 12 + offset - buffer_size);
		}
		std::uint32_t packet_size = network_utils::decode_network_int(buffer + offset);

		if(buffer_size - offset < packet_size)
		{
			return std::make_pair(false, packet_size + offset - buffer_size)
		}
		retutn std::make_pair(true, packet_size);
	}
}
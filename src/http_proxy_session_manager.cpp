#include "http_proxy_session_manager.hpp"

namespace http_proxy
{
    http_proxy_session_manager::http_proxy_session_manager(asio::ip::tcp::socket&& in_client_socket, asio::ip::tcp::socket&& in_server_socket, std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count, std::uint32_t _in_timeout, const std::string& rsa_key, bool _in_is_downgoing):
	http_proxy_connection(std::move(in_client_socket), std::move(in_server_socket), logger, in_connection_count, _in_timeout, rsa_key, "session_manager"),
	is_server_side(_in_is_downgoing)

	{

	}
	std::shared_ptr<http_proxy_session_manager> http_proxy_session_manager::create(asio::ip::tcp::socket&& in_client_socket, asio::ip::tcp::socket&& in_server_socket, std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count, std::uint32_t _in_timeout, const std::string& rsa_key, bool _in_is_downgoing)
	{
		return std::make_shared<http_proxy_session_manager>(std::move(in_client_socket), std::move(in_server_socket), logger, in_connection_count, _in_timeout, rsa_key, _in_is_downgoing);
	}
	void http_proxy_session_manager::post_send_task(std::uint32_t sender_session_idx, std::uint32_t session_idx, const unsigned char* send_buffer, std::uint32_t buffer_size)
	{
		return post_send_task(sender_session_idx, session_idx, send_buffer, buffer_size, session_data_cmd::session_data);
	}
	void http_proxy_session_manager::post_send_task(std::uint32_t sender_session_idx, std::uint32_t session_idx, const unsigned char* send_buffer, std::uint32_t buffer_size, session_data_cmd data_type)
	{
		
		strand.post([=, self = shared_from_this()](){
			send_task_desc cur_task{ sender_session_idx, session_idx, buffer_size,send_buffer, data_type };
			std::size_t queue_size = 0;
			bool send_in_progress = false;
			send_in_progress = !send_task_queue.empty();
			send_task_queue.push(cur_task);
			queue_size = send_task_queue.size();

			logger->debug("{} post_send_task sender_session_idx {} session_idx {} data_type {} size {}  send_in_progress {} queue size {}", logger_prefix, sender_session_idx, session_idx, static_cast<std::uint32_t>(data_type), buffer_size, send_in_progress, queue_size);
			if (!send_in_progress)
			{
				do_send_one();
			}
		}, asio::get_associated_allocator(strand));
		
	}
	void http_proxy_session_manager::post_read_task(std::shared_ptr<http_proxy_connection> _task_session, std::uint32_t min_read_size, std::uint32_t max_read_size)
	{
		logger->debug("{} post_read_task  session {} min_read_size {} max_read_size {}", logger_prefix, _task_session->connection_count, min_read_size, max_read_size);
		auto session_idx = _task_session->connection_count;
		strand.post([=, self = shared_from_this()]() {
			auto task_iter = _read_tasks.find(session_idx);
			if (task_iter == _read_tasks.end())
			{
				logger->warn("{} post_read_task for session {} fail , cant find read task", logger_prefix, session_idx);
				return;
			}
			auto& cur_read_task = task_iter->second;
			cur_read_task.min_read_size = min_read_size;
			cur_read_task.max_read_size = max_read_size;
			try_handle_packet_read(cur_read_task);
		}, asio::get_associated_allocator(strand));
	}

	void http_proxy_session_manager::prepare_read_buffer(std::shared_ptr<http_proxy_connection> _task_session, unsigned char* read_buffer, std::uint32_t max_read_size)
	{
		read_task_desc cur_task { _task_session->connection_count, 0, max_read_size, read_buffer, 0};
		_read_tasks[_task_session->connection_count] = cur_task;

	}
	void http_proxy_session_manager::do_send_one()
	{
		auto cur_task = send_task_queue.front();
		std::uint32_t send_size = 0;
		bool valid_session = true;
		if (_sessions.find(cur_task.session_idx) == _sessions.end() && cur_task.session_idx != connection_count)
		{
			valid_session = false;
		}
		if (!valid_session)
		{
			if(is_server_side)
			{
				on_client_data_send(0);
			}
			else
			{
				on_server_data_send(0);
			}
			
			return;
		}
		unsigned char* buffer_begin = server_send_buffer.data();
		if(is_server_side)
		{
			buffer_begin = client_send_buffer.data();
		}
		send_size = cur_task.buffer_size;
		network_utils::encode_network_int(buffer_begin, send_size);
		network_utils::encode_network_int(buffer_begin + 4, static_cast<std::uint32_t>(cur_task.data_type));
		network_utils::encode_network_int(buffer_begin + 8, cur_task.session_idx);
		if(send_size)
		{
			std::copy(cur_task.buffer, cur_task.buffer + cur_task.buffer_size, buffer_begin + DATA_HEADER_LEN);
			if(encryptor && connection_state != proxy_connection_state::send_cipher_data)
			{
				logger->debug("{} before encrypt data hash is {}", logger_prefix, aes_generator::checksum(buffer_begin + DATA_HEADER_LEN, send_size));
				encryptor->transform(buffer_begin + DATA_HEADER_LEN, send_size, 128);
				logger->debug("{} after encrypt data hash is {}", logger_prefix, aes_generator::checksum(buffer_begin + DATA_HEADER_LEN, send_size));
			}
			if (connection_state == proxy_connection_state::send_cipher_data)
			{
				connection_state = proxy_connection_state::session_tranfer;
			}

		}
		
		if(is_server_side)
		{
			async_send_data_to_client(buffer_begin, 0, send_size + DATA_HEADER_LEN);
		}
		else
		{
			async_send_data_to_server(buffer_begin, 0, send_size + DATA_HEADER_LEN);
		}
	}
	void http_proxy_session_manager::on_client_data_send(std::uint32_t bytes_transferred)
	{

		bool remain_progress = false;
		send_task_desc cur_task;
		logger->debug("{} http_proxy_session_manager::on_client_data_send bytes_transferred {}", logger_prefix, bytes_transferred);
		cur_task = send_task_queue.front();
		send_task_queue.pop();
		remain_progress = !send_task_queue.empty();

		if (bytes_transferred && cur_task.sender_session_idx != connection_count && cur_task.data_type == session_data_cmd::session_data)
		{

			std::shared_ptr<http_proxy_connection> cur_session;
			auto the_session_iter = _sessions.find(cur_task.sender_session_idx);
			if (the_session_iter != _sessions.end())
			{
				cur_session = the_session_iter->second;
			}
			if (cur_session)
			{
				cur_session->on_client_data_send(bytes_transferred);
			}
		}
		
		if(remain_progress)
		{
			do_send_one();
		}
	}
	void http_proxy_session_manager::on_server_data_send(std::uint32_t bytes_transferred)
	{
		bool remain_progress = false;
		send_task_desc cur_task;
		logger->debug("{} http_proxy_session_manager::on_server_data_send bytes_transferred {}", logger_prefix, bytes_transferred);
		cur_task = send_task_queue.front();
		send_task_queue.pop();
		remain_progress = !send_task_queue.empty();

		if (bytes_transferred && cur_task.sender_session_idx != connection_count)
		{
			std::shared_ptr<http_proxy_connection> cur_session;
			auto the_session_iter = _sessions.find(cur_task.sender_session_idx);
			if (the_session_iter != _sessions.end())
			{
				cur_session = the_session_iter->second;
			}

			if (cur_session)
			{
				cur_session->on_server_data_send(bytes_transferred);
			}
		}
		
		if(remain_progress)
		{
			do_send_one();
		}
	}
	void http_proxy_session_manager::add_session(std::shared_ptr<http_proxy_connection> _new_session)
	{
		std::uint32_t session_count = _new_session->connection_count;
		logger->debug("{} add session {}", logger_prefix, session_count);
		
		_sessions[session_count] = _new_session;
		if (is_server_side)
		{
			// from server to host
			prepare_read_buffer(_new_session, _new_session->client_read_buffer.data(), BUFFER_LENGTH);
		}
		else
		{
			//from ua to client
			prepare_read_buffer(_new_session, _new_session->server_read_buffer.data(), BUFFER_LENGTH);
		}
		
		post_send_task(session_count, session_count, nullptr, 0, session_data_cmd::new_session);
		
	}
	bool http_proxy_session_manager::remove_session(std::uint32_t _session_idx)
	{
		std::uint32_t remove_count = 0;
		remove_count = _sessions.erase(_session_idx);
		auto pre_task_iter = _read_tasks.find(_session_idx);
		if (pre_task_iter != _read_tasks.end())
		{
			for (const auto& i : pre_task_iter->second.receive_buffers)
			{
				delete[] i.first;
			}
			_read_tasks.erase(pre_task_iter);
		}
		
		if (remove_count >= 1)
		{
			post_send_task(_session_idx, _session_idx, nullptr, 0, session_data_cmd::remove_session);
			logger->debug("{} remove session {}", logger_prefix, _session_idx);
			return true;
		}
		else
		{
			return false;
		}
		
	}
	void http_proxy_session_manager::on_data_arrived(std::uint32_t bytes_transferred, const unsigned char* read_buffer)
	{
		logger->debug("{} http_proxy_session_manager::on_data_arrived  size {} buffer_offset {} read_offset {}", logger_prefix, bytes_transferred, buffer_offset, read_offset);
		buffer_offset += bytes_transferred;
		bytes_transferred = buffer_offset - read_offset;
		logger->debug("{} buffer_offset {} read_offset {}", logger_prefix, buffer_offset, read_offset);
		while (true)
		{
			std::uint32_t offset = 0;
			auto cur_parse_result = parse_data(read_buffer, buffer_offset, read_offset);
			logger->debug("{} parse result first {} second {}", logger_prefix, cur_parse_result.first, cur_parse_result.second);
			if (!cur_parse_result.first)
			{
				if (is_server_side)
				{
					async_read_data_from_client(true, cur_parse_result.second, BUFFER_LENGTH);
				}
				else
				{
					async_read_data_from_server(true, cur_parse_result.second, BUFFER_LENGTH);
				}

				return;
			}
			session_data_cmd data_type = static_cast<session_data_cmd>(network_utils::decode_network_int(read_buffer + read_offset + 4));
			std::uint32_t session_idx = network_utils::decode_network_int(read_buffer + read_offset + 8);
			logger->debug("{} http_proxy_session_manager::after parse data_type {} session_idx {}  size {}", logger_prefix, static_cast<std::uint32_t>(data_type), session_idx, cur_parse_result.second);
			logger->debug("{} before decrypt hash is {}", logger_prefix, aes_generator::checksum(read_buffer + read_offset + DATA_HEADER_LEN, cur_parse_result.second));
			if (decryptor && connection_state != proxy_connection_state::read_cipher_data)
			{
				
				decryptor->decrypt(read_buffer + read_offset + DATA_HEADER_LEN, _decrypt_buffer.data(), cur_parse_result.second);
			}
			else
			{
				std::copy(read_buffer + read_offset + DATA_HEADER_LEN, read_buffer + read_offset + DATA_HEADER_LEN + cur_parse_result.second, _decrypt_buffer.data());
			}
			logger->debug("{} after decrypt hash is {}", logger_prefix, aes_generator::checksum(_decrypt_buffer.data(), cur_parse_result.second));
			read_offset += DATA_HEADER_LEN + cur_parse_result.second;
			if (data_type != session_data_cmd::session_data)
			{
				on_control_data_arrived(session_idx, data_type, cur_parse_result.second, _decrypt_buffer.data());
			}
			else
			{
				on_packet_data_arrived(session_idx, cur_parse_result.second, _decrypt_buffer.data());
			}
		}
	}
	void http_proxy_session_manager::on_packet_data_arrived(std::uint32_t session_idx, std::uint32_t buffer_len, const unsigned char* _decrypt_buffer)
	{
		std::shared_ptr<http_proxy_connection> _cur_session;
		auto cur_session_iter = _sessions.find(session_idx);
		if (cur_session_iter != _sessions.end())
		{
			_cur_session = cur_session_iter->second;
		}
		else
		{
			logger->warn("{} on_packet_data_arrived but session {} not found", logger_prefix, session_idx);
			return;
		}
		logger->debug("{} on_packet_data_arrived len {} for session {}", logger_prefix, buffer_len, session_idx);
		auto cur_task_iter = _read_tasks.find(session_idx);
		if (cur_task_iter == _read_tasks.end())
		{
			remove_session(session_idx);
			logger->warn("{} on_packet_data_arrived but session {} read task not found", logger_prefix, session_idx);
			return;

		}
		auto& cur_read_task = cur_task_iter->second;

		if (cur_read_task.receive_buffers.empty())
		{
			auto new_buffer = new unsigned char[BUFFER_LENGTH];
			logger->debug("{} create new buffer for session {} total buffer size {}", logger_prefix, session_idx, 1);
			std::copy(_decrypt_buffer, _decrypt_buffer + buffer_len, new_buffer);
			cur_read_task.receive_buffers.emplace_back(new_buffer, buffer_len);
		}
		else
		{
			auto [last_buffer, used_size] = cur_read_task.receive_buffers.back();
			if (BUFFER_LENGTH - used_size >= buffer_len)
			{
				std::copy(_decrypt_buffer, _decrypt_buffer + buffer_len, last_buffer + used_size);
				cur_read_task.receive_buffers.back().second += buffer_len;
			}
			else
			{
				auto temp_size_len = BUFFER_LENGTH - used_size;
				auto remain_size_len = buffer_len - temp_size_len;
				std::copy(_decrypt_buffer, _decrypt_buffer + temp_size_len, last_buffer + used_size);
				cur_read_task.receive_buffers.back().second += temp_size_len;
				auto new_buffer = new unsigned char[BUFFER_LENGTH];
				std::copy(_decrypt_buffer + temp_size_len, _decrypt_buffer + buffer_len, new_buffer);
				cur_read_task.receive_buffers.emplace_back(new_buffer, remain_size_len);
				logger->debug("{} create new buffer for session {} total buffer size {}", logger_prefix, session_idx, cur_read_task.receive_buffers.size());
			}
		}


		// for now the buffers are set
		cur_read_task.already_read_size += buffer_len;
		try_handle_packet_read(cur_read_task);
	}
	void http_proxy_session_manager::try_handle_packet_read(read_task_desc& cur_read_task)
	{
		
		auto session_idx = cur_read_task.session_idx;
		logger->debug("{} try_handle_packet_read for session {} already_read_size {}", logger_prefix, session_idx, cur_read_task.already_read_size);
		auto session_iter = _sessions.find(session_idx);
		if (session_iter == _sessions.end())
		{
			logger->warn("{} try_handle_packet_read cant find session {}", logger_prefix, session_idx);
			return;
		}
		auto _cur_session = session_iter->second;
		if (!cur_read_task.min_read_size)
		{
			// wait for session to initial read
			logger->debug("{} cur_read_task for session {} min_read_size 0", logger_prefix, session_idx);
			return;
		}
		if (cur_read_task.already_read_size < cur_read_task.min_read_size)
		{
			// buffer len is too small
			logger->debug("{} cur_read_task for session {} min_read_size {} already_read_size {} too small ", logger_prefix, session_idx, cur_read_task.min_read_size, cur_read_task.already_read_size);
			return;
		}
		auto need_size = cur_read_task.max_read_size;
		if (cur_read_task.receive_buffers.empty())
		{
			logger->error("{} receive_buffers empty for session {} while already_read_size {}, min_read_size {}", logger_prefix, session_idx, cur_read_task.already_read_size, cur_read_task.min_read_size);
			std::cout << std::endl;
		}
		std::uint32_t read_size = 0;
		while (need_size)
		{
			auto[cur_buffer, used_size] = cur_read_task.receive_buffers.front();
			if (used_size > need_size)
			{
				std::copy(cur_buffer, cur_buffer + need_size, cur_read_task.buffer + read_size);
				std::copy(cur_buffer + need_size, cur_buffer + used_size, cur_buffer);
				cur_read_task.receive_buffers.front().second = used_size - need_size;
				read_size += need_size;
				need_size = 0;
			}
			else
			{
				std::copy(cur_buffer, cur_buffer + used_size, cur_read_task.buffer + read_size);
				read_size += used_size;
				need_size -= used_size;
				delete[] cur_buffer;

				for (int i = 0; i < cur_read_task.receive_buffers.size() - 1; i++)
				{
					std::swap(cur_read_task.receive_buffers[i], cur_read_task.receive_buffers[i + 1]);
				}
				cur_read_task.receive_buffers.pop_back();
				logger->debug("{} free buffer for session {} total buffer size {}", logger_prefix, session_idx, cur_read_task.receive_buffers.size());
			}
			if (cur_read_task.receive_buffers.empty())
			{
				break;
			}
		}
		auto remain_len = cur_read_task.already_read_size - read_size;
		cur_read_task.already_read_size = remain_len;
		cur_read_task.min_read_size = 0;
		logger->debug("{} send data to session {} size {} already_read_size {}", logger_prefix, session_idx, read_size, cur_read_task.already_read_size);
		if (is_server_side)
		{
			_cur_session->strand.post([=]() {
				_cur_session->on_client_data_arrived(read_size);
			}, asio::get_associated_allocator(_cur_session->strand));
		}
		else
		{
			_cur_session->strand.post([=]()
				{
					_cur_session->on_server_data_arrived(read_size);
				}, asio::get_associated_allocator(_cur_session->strand));
		}
		

	}
	void http_proxy_session_manager::on_server_data_arrived(std::uint32_t bytes_transferred)
	{
		on_data_arrived(bytes_transferred, server_read_buffer.data());
	}
	void http_proxy_session_manager::on_client_data_arrived(std::uint32_t bytes_transferred)
	{
		on_data_arrived(bytes_transferred, client_read_buffer.data());
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
			this->set_timer(timer_type::up_read);
		}
		
		asio::async_read(this->server_socket,
			asio::buffer(server_read_buffer.data() + buffer_offset, at_most_size),
			asio::transfer_at_least(at_least_size),
			asio::bind_executor(this->strand, [this, self](const error_code& error, std::size_t bytes_transferred)
		{
			if (this->cancel_timer(timer_type::up_read))
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
		logger->debug("{} async_read_data_from_client begin", logger_prefix);
		if(read_offset > BUFFER_LENGTH)
		{
			std::copy(client_read_buffer.data() + read_offset, client_read_buffer.data() + buffer_offset, client_read_buffer.data());
			buffer_offset -= read_offset;
			read_offset = 0;
		}
		auto self(this->shared_from_this());
		if (set_timer)
		{
			this->set_timer(timer_type::down_read);
		}
		
		asio::async_read(this->client_socket,
			asio::buffer(client_read_buffer.data() + buffer_offset, at_most_size),
			asio::transfer_at_least(at_least_size),
			asio::bind_executor(this->strand, [this, self](const error_code& error, std::size_t bytes_transferred)
		{
			if (this->cancel_timer(timer_type::down_read))
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

	std::pair<bool, std::uint32_t> http_proxy_session_manager::parse_data(const unsigned char* buffer, std::uint32_t buffer_size, std::uint32_t offset)
	// bool: get one complete packet
	// uint32_t if bool is true represent the packet size else at least more size to read
	// the packet size doesnt inlcude the DATA_HEADER_LEN bytes header 
	{
		if(buffer_size - offset < DATA_HEADER_LEN)
		{
			return std::make_pair(false, DATA_HEADER_LEN + offset - buffer_size);
		}
		std::uint32_t packet_size = network_utils::decode_network_int(buffer + offset);
		logger->debug("{} parse_data packet_size {} buffer_size {} offset {}", logger_prefix, packet_size, buffer_size, offset);
		if(buffer_size - offset < packet_size + DATA_HEADER_LEN)
		{
			return std::make_pair(false, packet_size + DATA_HEADER_LEN + offset - buffer_size);
		}
		return std::make_pair(true, packet_size);
	}
	void http_proxy_session_manager::on_control_data_arrived(std::uint32_t connection_idx, session_data_cmd cmd_type, std::uint32_t data_size, const unsigned char* buffer)
	{
		return;
	}
	void http_proxy_session_manager::close_connection()
	{
		std::vector<std::shared_ptr<http_proxy_connection>> temp_sessions;
		for (auto& one_session : _sessions)
		{
			temp_sessions.push_back(one_session.second);
		}

		for (auto& one_session : temp_sessions)
		{
			one_session->close_connection();
		}
		_read_tasks.clear();
		std::queue<send_task_desc> swap_queue;
		send_task_queue.swap(swap_queue);
		
		http_proxy_connection::close_connection();
	}
}
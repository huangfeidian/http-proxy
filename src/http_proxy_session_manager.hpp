#pragma once
#include <unordered_map>
#include <queue>
#include <mutex>

#include "http_proxy_connection_context.hpp"
#include "http_proxy_connection.hpp"

namespace azure_proxy
{
    class http_proxy_session_manager: public http_proxy_connection
    {
    public:
        struct send_task_desc
        {
			std::uint32_t sender_session_idx;
            std::uint32_t session_idx;
            std::uint32_t buffer_size;
            const unsigned char* buffer;
			session_data_cmd data_type;
			
		};
        struct read_task_desc
        {
            std::uint32_t session_idx;
			std::uint32_t min_read_size;
            std::uint32_t max_read_size;
            unsigned char* buffer;
			std::uint32_t already_read_size;	// sometime this is the buffer len sometimes this is window buffer len
			std::uint32_t window_buffer_index; // sometimes the default buffer is full so we must use the 64k window buffer to cache the incomming data
		};
    public:
        http_proxy_session_manager(asio::ip::tcp::socket&& in_client_socket, asio::ip::tcp::socket&& in_server_socket, std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count, std::uint32_t _in_timeout, const std::string& rsa_key, bool _in_is_downgoing);
        static std::shared_ptr<http_proxy_session_manager> create(asio::ip::tcp::socket&& in_client_socket, asio::ip::tcp::socket&& in_server_socket, std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count, std::uint32_t _in_timeout, const std::string& rsa_key, bool _in_is_downgoing);
    public:
        void post_send_task(std::uint32_t sender_session_idx, ::uint32_t _task_session, const unsigned char* send_buffer, std::uint32_t buffer_size);

        void post_read_task(std::shared_ptr<http_proxy_connection> _task_session, std::uint32_t min_read_size, std::uint32_t max_read_size);
		void prepare_read_buffer(std::shared_ptr<http_proxy_connection> _task_session, unsigned char* read_buffer, std::uint32_t max_read_size);
    private:
        std::unordered_map<std::uint32_t, std::shared_ptr<http_proxy_connection>> _sessions;
        std::unordered_map<std::uint32_t, read_task_desc> _read_tasks;
        std::queue<send_task_desc> send_task_queue;
		const bool is_downgoing; // true if income connection is ua else false for server side session manager
		std::uint32_t buffer_offset;
		std::uint32_t read_offset;
		std::array<unsigned char, MAX_HTTP_BUFFER_LENGTH> _decrypt_buffer;

		std::array<unsigned char, BUFFER_WINDOW_LENGTH * BUFFER_WINDOW_CAPACITY> read_window_buffer;
		std::array<unsigned int, BUFFER_WINDOW_CAPACITY> used_buffer_window;
		
    public:
		
		void add_session(std::shared_ptr<http_proxy_connection> _new_session);
        bool remove_session(std::uint32_t _session_idx);
    protected:
        
		void do_send_one();
		void on_server_data_send(std::uint32_t bytes_transferred);
		void on_client_data_send(std::uint32_t bytes_transferred);
		void post_send_task(std::uint32_t sender_session_idx, std::uint32_t session_idx, const unsigned char* send_buffer, std::uint32_t buffer_size, session_data_cmd data_type);

		void on_data_arrived(std::uint32_t byte_transfered, const unsigned char* read_buffer);
		void on_server_data_arrived(std::uint32_t bytes_transferred);
		void on_client_data_arrived(std::uint32_t bytes_transferred);
		void async_read_data_from_server(bool set_timer, std::uint32_t at_least_size = 1, std::uint32_t at_most_size = BUFFER_LENGTH);
		void async_read_data_from_client(bool set_timer, std::uint32_t at_least_size = 1, std::uint32_t at_most_size = BUFFER_LENGTH);
        virtual void on_control_data_arrived(std::uint32_t connection_idx, session_data_cmd cmd_type, std::uint32_t data_size, const unsigned char* buffer);
		void on_packet_data_arrived(std::uint32_t connection_idx, std::uint32_t buffer_len, const unsigned char* _decrypt_buffer);
		void try_handle_packet_read(read_task_desc& cur_read_task);
		std::pair<bool, std::uint32_t> parse_data(const unsigned char* buffer, std::uint32_t buffer_size, std::uint32_t offset);
		virtual void close_connection();
		std::unordered_map<std::uint32_t, std::uint32_t> mapped_session;

	};

}

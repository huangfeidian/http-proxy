#pragma once
#include <unorderd_map>
#include <queue>
#include "http_proxy_client_session.hpp"
#include "http_proxy_connection_context.hpp
"
namespace azure_proxy
{
    class http_proxy_session_manager: public http_proxy_connection
    {
    public:
        struct send_task_desc
        {
            std::uint32_t session_idx;
            std::uint32_t buffer_size;
            const unsigned char* buffer;
        }
        struct read_task_desc
        {
            std::uint32_t session_idx;
            std::uint32_t min_read_size;
            std::uint32_t max_read_size;
            const unsigned char* buffer;
        }
    public:
        http_proxy_session_manager(std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count);
        static std::shared_ptr<http_proxy_session_manager> create(std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count);
    public:
        post_send_task(std::shared_ptr<http_proxy_connection> _task_session, const unsigned char* send_buffer, std::uint32_t buffer_size);
        post_read_task(std::shared_ptr<http_proxy_connection> _task_session, const unsigned char* read_buffer, std::uint32_t min_read_size, std::uint32_t max_read_size);
    private:
        std::unordered_map<std::uint32_t, std::weak_ptr<http_proxy_connection> _sessions;
        std::unordered_map<std::uint32_t, read_task_desc> _read_limits;
        std::queue<send_task_desc> send_buffer_queue;
    public:
        void add_session(std::shared_ptr<http_proxy_connection>& _new_session);
        bool remove_session(std::uint32_t _session_idx);
        bool encode_data(session_data_cmd _cmd, std::uint32_t session_idx, const unsigned char* buffer, std::uint32_t buffer_size, unsigned char* dest_buffer, std::uint32_t remain_size);
    private:
        bool init_cipher();
    }

}

﻿#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>

#include <asio.hpp>
using error_code = asio::error_code;


namespace http_proxy {

class http_proxy_client_stat {
private:
    std::atomic<std::uint32_t> upgoing_bytes_in;
    std::atomic<std::uint32_t> upgoing_bytes_out;
    std::atomic<std::uint32_t> downgoing_bytes_in;
    std::atomic<std::uint32_t> downgoing_bytes_out;

    std::atomic<std::uint32_t> upgoing_rate_in;
    std::atomic<std::uint32_t> upgoing_rate_out;
    std::atomic<std::uint32_t> downgoing_rate_in;
    std::atomic<std::uint32_t> downgoing_rate_out;

    std::deque<std::uint32_t> upgoing_rate_in_queue;
    std::deque<std::uint32_t> upgoing_rate_out_queue;
    std::deque<std::uint32_t> downgoing_rate_in_queue;
    std::deque<std::uint32_t> downgoing_rate_out_queue;

    std::atomic<std::uint32_t> upgoing_speed_in;
    std::atomic<std::uint32_t> upgoing_speed_out;
    std::atomic<std::uint32_t> downgoing_speed_in;
    std::atomic<std::uint32_t> downgoing_speed_out;

    std::atomic<std::uint64_t> total_bytes_of_upgoing_in;
    std::atomic<std::uint64_t> total_bytes_of_upgoing_out;
    std::atomic<std::uint64_t> total_bytes_of_downgoing_in;
    std::atomic<std::uint64_t> total_bytes_of_downgoing_out;

    std::atomic<std::uint32_t> current_connections;
public:
    void start_stat(asio::io_context& io_context);
private:
    http_proxy_client_stat();
    void callback(const error_code& error, std::shared_ptr<asio::basic_waitable_timer<std::chrono::steady_clock>> sp_timer);
public:
    std::uint32_t increase_current_connections();
    std::uint32_t decrease_current_connections();

    void on_upgoing_recv(std::uint32_t bytes);
    void on_upgoing_send(std::uint32_t bytes);
    void on_downgoing_recv(std::uint32_t bytes);
    void on_downgoing_send(std::uint32_t bytes);

    std::uint64_t get_upgoing_total_bytes_recv() const;
    std::uint64_t get_upgoing_total_bytes_send() const;
    std::uint32_t get_upgoing_rate_recv() const;
    std::uint32_t get_upgoing_rate_send() const;
    std::uint32_t get_upgoing_speed_recv() const;
    std::uint32_t get_upgoing_speed_send() const;

    std::uint64_t get_downgoing_total_bytes_recv() const;
    std::uint64_t get_downgoing_total_bytes_send() const;
    std::uint32_t get_downgoing_rate_recv() const;
    std::uint32_t get_downgoing_rate_send() const;
    std::uint32_t get_downgoing_speed_recv() const;
    std::uint32_t get_downgoing_speed_send() const;

    std::uint32_t get_current_connections() const;
public:
    static http_proxy_client_stat& get_instance();
};

} // namespace http_proxy


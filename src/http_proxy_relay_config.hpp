

#ifndef HTTP_PROXY_SERVER_CONFIG_HPP
#define HTTP_PROXY_SERVER_CONFIG_HPP

#include <cassert>
#include <map>
#include <stdexcept>
#include <string>
#include <spdlog/spdlog.h>

#include <atomic>
namespace http_proxy {

	class http_proxy_relay_config {
		std::map<std::string, int> config_map_int;
		std::map<std::string, std::string> config_map_str;
		std::atomic<std::uint32_t> connection_count;
	private:
		template<typename T>
		T get_config_value(const std::string& key) const;
		template<typename T>
		void set_config_value(const std::string& key, const T& value);
		http_proxy_relay_config();

	public:
		bool load_config(const std::string& config_filename);
		std::string get_proxy_server_address() const;
		int get_proxy_server_port() const;
		std::string get_bind_address() const;
		int get_listen_port() const;
		int get_timeout() const;
		int get_workers() const;
		spdlog::level::level_enum get_log_level() const;
		spdlog::level::level_enum get_console_log_level() const;
		spdlog::level::level_enum get_file_log_level() const;
		std::string get_log_file_name() const;
		std::uint32_t increase_connection_count();
		static http_proxy_relay_config& get_instance();
	};

} // namespace http_proxy

#endif

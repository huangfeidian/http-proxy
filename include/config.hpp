namespace http_proxy
{
	static const std::size_t MAX_REQUEST_HEADER_LENGTH = 10240;
	static const std::size_t MAX_RESPONSE_HEADER_LENGTH = 10240;
	static const std::size_t BUFFER_LENGTH = 4096;
	static const std::size_t MAX_HTTP_BUFFER_LENGTH = 10240;
	static const std::size_t DATA_HEADER_LEN = 12; // packet_size + data_type + session_idx
	static const std::size_t BUFFER_WINDOW_LENGTH = 65536;			//  the default buffer window length
	static const std::size_t BUFFER_WINDOW_CAPACITY = 16;			// availble buffer window count
}
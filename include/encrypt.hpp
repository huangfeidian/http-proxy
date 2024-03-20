#pragma once

#include <cassert>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <vector>
#include <numeric>
#include "key_generator.hpp"
extern "C" {
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
}

namespace http_proxy
{

	class stream_encryptor
	{
	public:
		virtual void encrypt(const unsigned char* in, unsigned char* out, std::size_t length) = 0;
		void transform(unsigned char* data, std::size_t length, std::size_t block_size);

		void copy(const unsigned char* in, unsigned char* out, std::size_t length)
		{
			assert(in && out);
			std::memcpy(out, in, length);
		}
		virtual ~stream_encryptor()
		{
		}
	};

	class stream_decryptor
	{
	public:
		virtual void decrypt(const unsigned char* in, unsigned char* out, std::size_t length) = 0;
		virtual ~stream_decryptor()
		{
		}
		void copy(const unsigned char* in, unsigned char* out, std::size_t length)
		{
			assert(in && out);
			std::memcpy(out, in, length);
		}
	};

	class copy_encryptor : public stream_encryptor
	{
	public:
		copy_encryptor()
		{
		};
		virtual void encrypt(const unsigned char* in, unsigned char* out, std::size_t length)
		{
			assert(in && out);
			std::memcpy(out, in, length);
		}
		virtual ~copy_encryptor()
		{
		}
	};

	class aes_cfb128_encryptor : public stream_encryptor
	{
		AES_KEY aes_ctx;
		int num;
		unsigned char key[32];
		unsigned char ivec[16];
	public:
		aes_cfb128_encryptor(const unsigned char* key, std::uint32_t key_bits, unsigned char* ivec);

		void encrypt(const unsigned char* in, unsigned char* out, std::size_t length)override;

		virtual ~aes_cfb128_encryptor()
		{
		}
	};

	class aes_cfb128_decryptor : public stream_decryptor
	{
		AES_KEY aes_ctx;
		int num;
		unsigned char key[32];
		unsigned char ivec[16];
	public:
		aes_cfb128_decryptor(const unsigned char* key, std::uint32_t key_bits, unsigned char* ivec);

		void decrypt(const unsigned char* in, unsigned char* out, std::size_t length)override;

		virtual ~aes_cfb128_decryptor()
		{
		}
	};

	class aes_cfb8_encryptor : public stream_encryptor
	{
		AES_KEY aes_ctx;
		int num;
		unsigned char key[32];
		unsigned char ivec[16];
	public:
		aes_cfb8_encryptor(const unsigned char* key, std::uint32_t key_bits, unsigned char* ivec);

		void encrypt(const unsigned char* in, unsigned char* out, std::size_t length)override;

		virtual ~aes_cfb8_encryptor()
		{
		}
	};

	class aes_cfb8_decryptor : public stream_decryptor
	{
		AES_KEY aes_ctx;
		int num;
		unsigned char key[32];
		unsigned char ivec[16];
	public:
		aes_cfb8_decryptor(const unsigned char* key, std::uint32_t key_bits, unsigned char* ivec);

		void decrypt(const unsigned char* in, unsigned char* out, std::size_t length)override;

		virtual ~aes_cfb8_decryptor()
		{
		}
	};

	class aes_cfb1_encryptor : public stream_encryptor
	{
		AES_KEY aes_ctx;
		int num;
		unsigned char key[32];
		unsigned char ivec[16];
	public:
		aes_cfb1_encryptor(const unsigned char* key, std::uint32_t key_bits, unsigned char* ivec);

		void encrypt(const unsigned char* in, unsigned char* out, std::size_t length)override;

		virtual ~aes_cfb1_encryptor()
		{
		}
	};

	class copy_decryptor : public stream_decryptor
	{
	public:
		copy_decryptor()
		{
		};
		void decrypt(const unsigned char* in, unsigned char* out, std::size_t length)
		{
			assert(in && out);
			std::memcpy(out, in, length);
		}
		virtual ~copy_decryptor()
		{
		}
	};

	class aes_cfb1_decryptor : public stream_decryptor
	{
		AES_KEY aes_ctx;
		int num;
		unsigned char key[32];
		unsigned char ivec[16];
	public:
		aes_cfb1_decryptor(const unsigned char* key, std::uint32_t key_bits, unsigned char* ivec);

		void decrypt(const unsigned char* in, unsigned char* out, std::size_t length) override;


		virtual ~aes_cfb1_decryptor()
		{
		}
	};

	class aes_ofb128_encryptor : public stream_encryptor
	{
		AES_KEY aes_ctx;
		int num;
		unsigned char key[32];
		unsigned char ivec[16];
	public:
		aes_ofb128_encryptor(const unsigned char* key, std::uint32_t key_bits, unsigned char* ivec);
		void encrypt(const unsigned char* in, unsigned char* out, std::size_t length) override;

		virtual ~aes_ofb128_encryptor()
		{
		}
	};

	class aes_ofb128_decryptor : public stream_decryptor
	{
		AES_KEY aes_ctx;
		int num;
		unsigned char key[32];
		unsigned char ivec[16];
	public:
		aes_ofb128_decryptor(const unsigned char* key, std::uint32_t key_bits, unsigned char* ivec);


		void decrypt(const unsigned char* in, unsigned char* out, std::size_t length) override;

		virtual ~aes_ofb128_decryptor()
		{
		}
	};

	// class aes_ctr128_encryptor : public stream_encryptor
	// {
	// 	AES_KEY aes_ctx;
	// 	unsigned int num;
	// 	unsigned char key[32];
	// 	unsigned char ivec[16];
	// 	unsigned char ecount_buf[16];
	// public:
	// 	aes_ctr128_encryptor(const unsigned char* key, std::uint32_t key_bits, unsigned char* ivec) : num(0)
	// 	{
	// 		assert(key && ivec);
	// 		assert(key_bits == 128 || key_bits == 192 || key_bits == 256);
	// 		std::memcpy(this->key, key, key_bits / 8);
	// 		std::memcpy(this->ivec, ivec, sizeof(this->ivec));
	// 		std::memset(this->ecount_buf, 0, sizeof(this->ecount_buf));
	// 		AES_set_encrypt_key(this->key, key_bits, &this->aes_ctx);
	// 	}

	// 	virtual void encrypt(const unsigned char* in, unsigned char* out, std::size_t length)
	// 	{
	// 		assert(in && out);
	// 		AES_ctr128_encrypt(in, out, length, &aes_ctx, this->ivec, this->ecount_buf, &this->num);
	// 	}

	// 	virtual ~aes_ctr128_encryptor()
	// 	{
	// 	}
	// };

	// class aes_ctr128_decryptor : public stream_decryptor
	// {
	// 	AES_KEY aes_ctx;
	// 	unsigned int num;
	// 	unsigned char key[32];
	// 	unsigned char ivec[16];
	// 	unsigned char ecount_buf[16];
	// public:
	// 	aes_ctr128_decryptor(const unsigned char* key, std::uint32_t key_bits, unsigned char* ivec) : num(0)
	// 	{
	// 		assert(key && ivec);
	// 		assert(key_bits == 128 || key_bits == 192 || key_bits == 256);
	// 		std::memcpy(this->key, key, key_bits / 8);
	// 		std::memcpy(this->ivec, ivec, sizeof(this->ivec));
	// 		std::memset(this->ecount_buf, 0, sizeof(this->ecount_buf));
	// 		AES_set_encrypt_key(this->key, key_bits, &this->aes_ctx);
	// 	}

	// 	virtual void decrypt(const unsigned char* in, unsigned char* out, std::size_t length)
	// 	{
	// 		assert(in && out);
	// 		AES_ctr128_encrypt(in, out, length, &aes_ctx, this->ivec, this->ecount_buf, &this->num);
	// 	}

	// 	virtual ~aes_ctr128_decryptor()
	// 	{
	// 	}
	// };

	enum class rsa_padding
	{
		pkcs1_padding,
		pkcs1_oaep_padding,
		sslv23_padding,
		no_padding
	};

	class rsa
	{
		bool is_pub;
		std::shared_ptr<RSA> rsa_handle;
		const std::string key_;
	public:
		rsa(const std::string& key);


		int encrypt(int flen, unsigned char* from, unsigned char* to, rsa_padding padding);


		int decrypt(int flen, const unsigned char* from, unsigned char* to, rsa_padding padding);


		int modulus_size() const;

		const std::string& key() const
		{
			return key_;
		}
		bool is_public_key() const
		{
			return is_pub;
		}
	private:
		int rsa_padding2int(rsa_padding padding)
		{
			switch (padding)
			{
			case rsa_padding::pkcs1_padding:
				return RSA_PKCS1_PADDING;
				break;
			case rsa_padding::pkcs1_oaep_padding:
				return RSA_PKCS1_OAEP_PADDING;
				break;
			case rsa_padding::sslv23_padding:
				return RSA_NO_PADDING;
				break;
			default:
				return RSA_NO_PADDING;
			}
		}
	};

	class aes_generator
	{
		//cipher code
		// 0x00 aes-128-cfb
		// 0x01 aes-128-cfb8
		// 0x02 aes-128-cfb1
		// 0x03 aes-128-ofb
		// 0x04 aes-128-ctr
		// 0x05 aes-192-cfb
		// 0x06 aes-192-cfb8
		// 0x07 aes-192-cfb1
		// 0x08 aes-192-ofb
		// 0x09 aes-192-ctr
		// 0x0A aes-256-cfb
		// 0x0B aes-256-cfb8
		// 0x0C aes-256-cfb1
		// 0x0D aes-256-ofb
		// 0x0E aes-256-ctr
	public:
		static bool generate(const std::string& cipher_name, char& cipher_code, std::vector<unsigned char>& ivec, std::vector<unsigned char>& key_vec, std::unique_ptr<stream_encryptor>& encryptor, std::unique_ptr<stream_decryptor>& decryptor);

		static std::uint64_t checksum(const unsigned char* begin, std::uint32_t length)
		{
			std::uint64_t total = 0;
			return std::accumulate(begin, begin + length, total);
			return total;
		}
		static std::uint64_t checksum(const char* begin, std::uint32_t length)
		{
			return checksum(reinterpret_cast<const unsigned char*>(begin), length);
		}
	};
	class network_utils
	{
	public:
		static void encode_network_int(unsigned char* buffer_begin, std::uint32_t value)
		{

			buffer_begin[3] = value % 256;
			value = value >> 8;
			buffer_begin[2] = value % 256;
			value = value >> 8;
			buffer_begin[1] = value % 256;
			value = value >> 8;
			buffer_begin[0] = value % 256;
		}
		static uint32_t decode_network_int(const unsigned char* buffer)
		{
			std::uint32_t result = 0;
			result = (result << 8) + static_cast<uint8_t>(buffer[0]);
			result = (result << 8) + static_cast<uint8_t>(buffer[1]);
			result = (result << 8) + static_cast<uint8_t>(buffer[2]);
			result = (result << 8) + static_cast<uint8_t>(buffer[3]);
			return result;
		}
	};
} // namespace http_proxy

/*
 *    encrypt.hpp:
 *
 *    Copyright (C) 2014-2015 limhiaoing <blog.poxiao.me> All Rights Reserved.
 *
 */

#ifndef AZURE_ENCRYPT_HPP
#define AZURE_ENCRYPT_HPP

#include <cassert>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <vector>
#include "key_generator.hpp"
extern "C" {
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
}

namespace azure_proxy
{

	class stream_encryptor
	{
	public:
		virtual void encrypt(const unsigned char* in, unsigned unsigned char* out, std::size_t length) = 0;
		void transform(unsigned char* data, std::size_t length, std::size_t block_size)
		{
			std::vector<unsigned char> temp_buffer(block_size, 0);
			for (std::size_t i = 0; i * block_size < length; i++)
			{
				std::size_t cur_block_size = block_size;
				if (length - i * block_size < block_size)
				{
					cur_block_size = length % block_size;
				}
				encrypt(data + i * block_size, &temp_buffer[0], cur_block_size);
				std::copy(&temp_buffer[0], &temp_buffer[0] + cur_block_size, data + i * block_size);
			}

		}
		void copy(const unsigned char* in, unsigned unsigned char* out, std::size_t length)
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
		void copy(const unsigned char* in, unsigned unsigned char* out, std::size_t length)
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
		aes_cfb128_encryptor(const unsigned char* key, std::size_t key_bits, unsigned char* ivec) : num(0)
		{
			assert(key && ivec);
			assert(key_bits == 128 || key_bits == 192 || key_bits == 256);
			std::memcpy(this->key, key, key_bits / 8);
			std::memcpy(this->ivec, ivec, sizeof(this->ivec));
			AES_set_encrypt_key(this->key, key_bits, &this->aes_ctx);
		}

		virtual void encrypt(const unsigned char* in, unsigned char* out, std::size_t length)
		{
			assert(in && out);
			AES_cfb128_encrypt(in, out, length, &this->aes_ctx, this->ivec, &this->num, AES_ENCRYPT);
		}

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
		aes_cfb128_decryptor(const unsigned char* key, std::size_t key_bits, unsigned char* ivec) : num(0)
		{
			assert(key && ivec);
			assert(key_bits == 128 || key_bits == 192 || key_bits == 256);
			std::memcpy(this->key, key, key_bits / 8);
			std::memcpy(this->ivec, ivec, sizeof(this->ivec));
			AES_set_encrypt_key(this->key, key_bits, &this->aes_ctx);
		}

		virtual void decrypt(const unsigned char* in, unsigned char* out, std::size_t length)
		{
			assert(in && out);
			AES_cfb128_encrypt(in, out, length, &this->aes_ctx, this->ivec, &this->num, AES_DECRYPT);
		}

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
		aes_cfb8_encryptor(const unsigned char* key, std::size_t key_bits, unsigned char* ivec) : num(0)
		{
			assert(key && ivec);
			assert(key_bits == 128 || key_bits == 192 || key_bits == 256);
			std::memcpy(this->key, key, key_bits / 8);
			std::memcpy(this->ivec, ivec, sizeof(this->ivec));
			AES_set_encrypt_key(this->key, key_bits, &this->aes_ctx);
		}

		virtual void encrypt(const unsigned char* in, unsigned char* out, std::size_t length)
		{
			assert(in && out);
			AES_cfb8_encrypt(in, out, length, &this->aes_ctx, this->ivec, &this->num, AES_ENCRYPT);
		}

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
		aes_cfb8_decryptor(const unsigned char* key, std::size_t key_bits, unsigned char* ivec) : num(0)
		{
			assert(key && ivec);
			assert(key_bits == 128 || key_bits == 192 || key_bits == 256);
			std::memcpy(this->key, key, key_bits / 8);
			std::memcpy(this->ivec, ivec, sizeof(this->ivec));
			AES_set_encrypt_key(this->key, key_bits, &this->aes_ctx);
		}

		virtual void decrypt(const unsigned char* in, unsigned char* out, std::size_t length)
		{
			assert(in && out);
			AES_cfb8_encrypt(in, out, length, &this->aes_ctx, this->ivec, &this->num, AES_DECRYPT);
		}

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
		aes_cfb1_encryptor(const unsigned char* key, std::size_t key_bits, unsigned char* ivec) : num(0)
		{
			assert(key && ivec);
			assert(key_bits == 128 || key_bits == 192 || key_bits == 256);
			std::memcpy(this->key, key, key_bits / 8);
			std::memcpy(this->ivec, ivec, sizeof(this->ivec));
			AES_set_encrypt_key(this->key, key_bits, &this->aes_ctx);
		}

		virtual void encrypt(const unsigned char* in, unsigned char* out, std::size_t length)
		{
			assert(in && out);
			AES_cfb1_encrypt(in, out, length * 8, &this->aes_ctx, this->ivec, &this->num, AES_ENCRYPT);
		}

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
		virtual void decrypt(const unsigned char* in, unsigned char* out, std::size_t length)
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
		aes_cfb1_decryptor(const unsigned char* key, std::size_t key_bits, unsigned char* ivec) : num(0)
		{
			assert(key && ivec);
			assert(key_bits == 128 || key_bits == 192 || key_bits == 256);
			std::memcpy(this->key, key, key_bits / 8);
			std::memcpy(this->ivec, ivec, sizeof(this->ivec));
			AES_set_encrypt_key(this->key, key_bits, &this->aes_ctx);
		}

		virtual void decrypt(const unsigned char* in, unsigned char* out, std::size_t length)
		{
			assert(in && out);
			AES_cfb1_encrypt(in, out, length * 8, &this->aes_ctx, this->ivec, &this->num, AES_DECRYPT);
		}

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
		aes_ofb128_encryptor(const unsigned char* key, std::size_t key_bits, unsigned char* ivec) : num(0)
		{
			assert(key && ivec);
			assert(key_bits == 128 || key_bits == 192 || key_bits == 256);
			std::memcpy(this->key, key, key_bits / 8);
			std::memcpy(this->ivec, ivec, sizeof(this->ivec));
			AES_set_encrypt_key(this->key, key_bits, &this->aes_ctx);
		}

		virtual void encrypt(const unsigned char* in, unsigned char* out, std::size_t length)
		{
			assert(in && out);
			AES_ofb128_encrypt(in, out, length, &this->aes_ctx, this->ivec, &this->num);
		}
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
		aes_ofb128_decryptor(const unsigned char* key, std::size_t key_bits, unsigned char* ivec) : num(0)
		{
			assert(key && ivec);
			assert(key_bits == 128 || key_bits == 192 || key_bits == 256);
			std::memcpy(this->key, key, key_bits / 8);
			std::memcpy(this->ivec, ivec, sizeof(this->ivec));
			AES_set_encrypt_key(this->key, key_bits, &this->aes_ctx);
		}

		virtual void decrypt(const unsigned char* in, unsigned char* out, std::size_t length)
		{
			assert(in && out);
			AES_ofb128_encrypt(in, out, length, &this->aes_ctx, this->ivec, &this->num);
		}
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
	// 	aes_ctr128_encryptor(const unsigned char* key, std::size_t key_bits, unsigned char* ivec) : num(0)
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
	// 	aes_ctr128_decryptor(const unsigned char* key, std::size_t key_bits, unsigned char* ivec) : num(0)
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
	public:
		rsa(const std::string& key)
		{
			if (key.size() > 26 && std::equal(key.begin(), key.begin() + 26, "-----BEGIN PUBLIC KEY-----"))
			{
				this->is_pub = true;
			}
			else if (key.size() > 31 && std::equal(key.begin(), key.begin() + 31, "-----BEGIN RSA PRIVATE KEY-----"))
			{
				this->is_pub = false;
			}
			else
			{
				throw std::invalid_argument("invalid argument");
			}

			auto bio_handle = std::shared_ptr<BIO>(BIO_new_mem_buf(const_cast<char*>(key.data()), key.size()), BIO_free);
			if (bio_handle)
			{
				if (this->is_pub)
				{
					this->rsa_handle = std::shared_ptr<RSA>(PEM_read_bio_RSA_PUBKEY(bio_handle.get(), nullptr, nullptr, nullptr), RSA_free);
				}
				else
				{
					this->rsa_handle = std::shared_ptr<RSA>(PEM_read_bio_RSAPrivateKey(bio_handle.get(), nullptr, nullptr, nullptr), RSA_free);
				}
			}
			if (!this->rsa_handle)
			{
				throw std::invalid_argument("invalid argument");
			}
		}

		int encrypt(int flen, unsigned char* from, unsigned char* to, rsa_padding padding)
		{
			assert(from && to);
			int pad = this->rsa_padding2int(padding);
			if (this->is_pub)
			{
				return RSA_public_encrypt(flen, from, to, this->rsa_handle.get(), pad);
			}
			else
			{
				return RSA_private_encrypt(flen, from, to, this->rsa_handle.get(), pad);
			}
		}

		int decrypt(int flen, unsigned char* from, unsigned char* to, rsa_padding padding)
		{
			assert(from && to);
			int pad = this->rsa_padding2int(padding);
			if (this->is_pub)
			{
				return RSA_private_decrypt(flen, from, to, this->rsa_handle.get(), pad);
			}
			else
			{
				return RSA_private_decrypt(flen, from, to, this->rsa_handle.get(), pad);
			}
		}

		int modulus_size() const
		{
			return RSA_size(this->rsa_handle.get());
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
				return RSA_SSLV23_PADDING;
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
		static bool generate(const std::string& cipher_name, char& cipher_code, std::vector<unsigned char>& ivec, std::vector<unsigned char>& key_vec, std::unique_ptr<stream_encryptor>& encryptor, std::unique_ptr<stream_decryptor>& decryptor)
		{
			assert(cipher_name[3] == '-' && cipher_name[7] == '-');
			if (std::strcmp(cipher_name.c_str() + 8, "cfb") == 0 || std::strcmp(cipher_name.c_str() + 8, "cfb128") == 0)
			{
				//where is cfb-128
				// aes-xxx-cfb
				if (std::equal(cipher_name.begin() + 4, cipher_name.begin() + 7, "128"))
				{
					cipher_code = 0x00;
					key_vec.resize(128 / 8);
				}
				else if (std::equal(cipher_name.begin() + 4, cipher_name.begin() + 7, "192"))
				{
					cipher_code = 0x05;
					key_vec.resize(192 / 8);
				}
				else
				{
					cipher_code = 0x0A;
					key_vec.resize(256 / 8);
				}
				key_generator::get_instance().generate(ivec.data(), ivec.size());
				key_generator::get_instance().generate(key_vec.data(), key_vec.size());
				encryptor = std::unique_ptr<stream_encryptor>(new aes_cfb128_encryptor(key_vec.data(), key_vec.size() * 8, ivec.data()));
				decryptor = std::unique_ptr<stream_decryptor>(new aes_cfb128_decryptor(key_vec.data(), key_vec.size() * 8, ivec.data()));
				return true;
			}
			else if (std::strcmp(cipher_name.c_str() + 8, "cfb8") == 0)
			{
				// aes-xxx-cfb8
				if (std::equal(cipher_name.begin() + 4, cipher_name.begin() + 7, "128"))
				{
					cipher_code = 0x01;
					key_vec.resize(128 / 8);
				}
				else if (std::equal(cipher_name.begin() + 4, cipher_name.begin() + 7, "192"))
				{
					cipher_code = 0x06;
					key_vec.resize(192 / 8);
				}
				else
				{
					cipher_code = 0x0B;
					key_vec.resize(256 / 8);
				}
				key_generator::get_instance().generate(ivec.data(), ivec.size());
				key_generator::get_instance().generate(key_vec.data(), key_vec.size());
				encryptor = std::unique_ptr<stream_encryptor>(new aes_cfb8_encryptor(key_vec.data(), key_vec.size() * 8, ivec.data()));
				decryptor = std::unique_ptr<stream_decryptor>(new aes_cfb8_decryptor(key_vec.data(), key_vec.size() * 8, ivec.data()));
				return true;
			}
			else if (std::strcmp(cipher_name.c_str() + 8, "cfb1") == 0)
			{
				// aes-xxx-cfb1
				if (std::equal(cipher_name.begin() + 4, cipher_name.begin() + 7, "128"))
				{
					cipher_code = 0x02;
					key_vec.resize(128 / 8);
				}
				else if (std::equal(cipher_name.begin() + 4, cipher_name.begin() + 7, "192"))
				{
					cipher_code = 0x07;
					key_vec.resize(192 / 8);
				}
				else
				{
					cipher_code = 0x0C;
					key_vec.resize(256 / 8);
				}
				key_generator::get_instance().generate(ivec.data(), ivec.size());
				key_generator::get_instance().generate(key_vec.data(), key_vec.size());
				encryptor = std::unique_ptr<stream_encryptor>(new aes_cfb1_encryptor(key_vec.data(), key_vec.size() * 8, ivec.data()));
				decryptor = std::unique_ptr<stream_decryptor>(new aes_cfb1_decryptor(key_vec.data(), key_vec.size() * 8, ivec.data()));
				return true;
			}
			else if (std::strcmp(cipher_name.c_str() + 8, "ofb") == 0)
			{
				// aes-xxx-ofb
				if (std::equal(cipher_name.begin() + 4, cipher_name.begin() + 7, "128"))
				{
					cipher_code = 0x03;
					key_vec.resize(128 / 8);
				}
				else if (std::equal(cipher_name.begin() + 4, cipher_name.begin() + 7, "192"))
				{
					cipher_code = 0x08;
					key_vec.resize(192 / 8);
				}
				else
				{
					cipher_code = 0x0D;
					key_vec.resize(256 / 8);
				}
				key_generator::get_instance().generate(ivec.data(), ivec.size());
				key_generator::get_instance().generate(key_vec.data(), key_vec.size());
				encryptor = std::unique_ptr<stream_encryptor>(new aes_ofb128_encryptor(key_vec.data(), key_vec.size() * 8, ivec.data()));
				decryptor = std::unique_ptr<stream_decryptor>(new aes_ofb128_decryptor(key_vec.data(), key_vec.size() * 8, ivec.data()));
				return true;
			}
			// else if (std::strcmp(cipher_name.c_str() + 8, "ctr") == 0)
			// {
			// 	// aes-xxx-ctr
			// 	if (std::equal(cipher_name.begin() + 4, cipher_name.begin() + 7, "128"))
			// 	{
			// 		cipher_code = 0x04;
			// 		key_vec.resize(128 / 8);
			// 	}
			// 	else if (std::equal(cipher_name.begin() + 4, cipher_name.begin() + 7, "192"))
			// 	{
			// 		cipher_code = 0x09;
			// 		key_vec.resize(192 / 8);
			// 	}
			// 	else
			// 	{
			// 		cipher_code = 0x0E;
			// 		key_vec.resize(256 / 8);
			// 	}
			// 	std::fill(ivec.begin(), ivec.end(), 0);
			// 	key_generator::get_instance().generate(key_vec.data(), key_vec.size());
			// 	this->encryptor = std::unique_ptr<stream_encryptor>(new aes_ctr128_encryptor(key_vec.data(), key_vec.size() * 8, ivec.data()));
			// 	this->decryptor = std::unique_ptr<stream_decryptor>(new aes_ctr128_decryptor(key_vec.data(), key_vec.size() * 8, ivec.data()));
			// }
			// 7 ~ 22 ivec
			// 23 ~ key
			return false;
		}
	};
	
} // namespace azure_proxy

#endif

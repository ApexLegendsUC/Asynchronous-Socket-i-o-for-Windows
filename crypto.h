#ifndef _CRYPTO_H
#define _CRYPTO_H

//to-do: add noexcept flags to all applicable member functions.

#define SHA512_BYTELEN 64
#define SHA256_BYTELEN 32


namespace Crypto {
	class CryptContext {
	public:
		CryptContext() noexcept :CryptContext(NULL) {} ;
		CryptContext(HCRYPTPROV hProv) noexcept;
		CryptContext(CryptContext&& context);
		CryptContext(const CryptContext& context);
		~CryptContext();
		void operator=(const CryptContext& context);
		void operator=(CryptContext&& context);
		static bool delete_container(LPCTSTR container);
		HCRYPTPROV handle() { return hCryptProv; };
		bool acquired() const { return hCryptProv != NULL; };
		bool acquire(DWORD dwProvType) noexcept;
		static CryptContext static_acquire(DWORD dwProvType) {
			CryptContext cc;
			cc.acquire(dwProvType);
			return cc;
		};
		void release();
	private:
		HCRYPTPROV hCryptProv;
	};

	class hash {
	public:
		enum Algorithms {
			sha256,
			sha384,
			sha512,
			md5, //proven to be cryptographically insecure.
			hmac
		};
		hash(Algorithms algorithm, HCRYPTKEY hKey = NULL);
		hash(Algorithms algorithm, const CryptContext& context, HCRYPTKEY hKey = NULL);
		~hash();
		std::vector<BYTE> sign_hash();
		bool hash_data(LPCVOID data, DWORD dwDataLen);
		bool hash_key(HCRYPTKEY hKey);
		HCRYPTHASH handle() { return hHash; };
		bool available() const { return hHash != NULL; };
		DWORD get_hash_size();
		std::vector<BYTE> get_hash_bytes();
		HCRYPTHASH duplicate();
	private:
		HCRYPTHASH hHash;
		CryptContext context;
	};

	class AES {
	public:
		enum Algorithms {
			aes_128,
			aes_192,
			aes_256
		};
		AES();
		AES(AES&& other);
		AES(const AES& other);
		AES(CryptContext&& context);
		AES(const CryptContext& context);
		~AES();

		void operator=(AES&& other);
		void operator=(const AES& other);

		/*derive key from hash*/
		bool derive_key(Algorithms algorithm, const std::string& password);
		bool derive_key(Algorithms algorithm, const std::wstring& password);
		bool derive_key(Algorithms algorithm, const std::vector<BYTE>& password);
		/*generate key*/
		bool generate_key(Algorithms algorithm);
		bool Import(HCRYPTKEY hPubKey, const std::vector<BYTE>& data);
		std::vector<BYTE> Export(HCRYPTKEY hExpKey) const; //throws an exception if unable to export key for any reason.
		bool encrypt(PBYTE pData, PDWORD lpdwDataLen, DWORD dwBufferLen);
		bool decrypt(PBYTE pData, PDWORD lpdwDataLen);
		std::vector<BYTE> encrypt(const std::vector<BYTE>& data);
		std::vector<BYTE> decrypt(const std::vector<BYTE>& data);

		bool blockencrypt(PVOID pData, PDWORD lpdwDataLen, DWORD dwBufferLen);
		std::vector<BYTE> blockencrypt(LPCVOID pData, DWORD dwLen);
		bool blockdecrypt(PVOID pData, PDWORD lpdwDataLen);
		bool available() const { return hCryptKey != NULL; };
		HCRYPTKEY duplicate() const;
		HCRYPTKEY get() { return hCryptKey; };
		DWORD get_plaintext_encrypted_len(DWORD dwClearTextLen) //https://en.wikipedia.org/wiki/Plaintext
		{
			if (!dwBlockSize)
				return NULL;
			return (dwClearTextLen / dwBlockSize + 1) * dwBlockSize;
		};
		void release();
	private:
		DWORD GetAlgID(Algorithms alg);
		DWORD dwBlockSize;
		HCRYPTKEY hCryptKey;
		CryptContext context;
	};

	class RSA {
	public:
		enum Algorithms {
			rsa_1024 = 1024 << 16,
			rsa_2048 = 2048 << 16,
			rsa_4096 = 4096 << 16,
			rsa_8192 = 8192 << 16,
			rsa_16384 = 16384 << 16
		};
		enum Methods {
			signature,
			encryption
		};
		RSA();
		RSA(RSA&& other);
		RSA(const RSA& other) = delete;
		RSA(CryptContext&& context);
		RSA(const CryptContext& context);
		~RSA();

		void operator=(RSA&& other);
		void operator=(const RSA& other) = delete;

		bool generate(Methods method, Algorithms algorithm, DWORD dwFlags = CRYPT_EXPORTABLE);
		std::vector<BYTE> export_private_key(const std::string& password);
		std::vector<BYTE> export_private_key(const std::wstring& password);
		std::vector<BYTE> export_private_key(const std::vector<BYTE>& password);
		std::vector<BYTE> export_public_key();
		bool import_private_key(const std::vector<BYTE>& data, const std::string& password);
		bool import_private_key(const std::vector<BYTE>& data, const std::wstring& password);
		bool import_private_key(const std::vector<BYTE>& data, const std::vector<BYTE>& password);
		bool import_public_key(const std::vector<BYTE>& data);


		bool encrypt(PBYTE pData, PDWORD lpdwDataLen, DWORD dwBufferLen);
		bool decrypt(PBYTE pData, PDWORD lpdwDataLen);

		HCRYPTKEY get() { return hKey; }; //renamed from key() to get()
		bool available() const { return hKey != NULL; };
		void release();
		std::vector<BYTE> sign_data(const std::vector<BYTE>& data);
		std::vector<BYTE> sign_key(HCRYPTKEY key);
		bool verify_data(const std::vector<BYTE>& data, const std::vector<BYTE>& signature);
		bool verify_key(HCRYPTKEY hCryptKey, const std::vector<BYTE>& signature);
	private:
		HCRYPTKEY hKey;
		CryptContext context;
	};

	class Random {
	public:
		Random() noexcept;
		Random(const CryptContext& context);
		bool Generate(LPVOID pMemory, DWORD dwSize);
		bool available() const { return context.acquired(); };
	private:
		CryptContext context;
	};

};

#endif
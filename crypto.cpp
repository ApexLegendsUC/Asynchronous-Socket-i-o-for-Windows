#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Wincrypt.h>
#include <utility>
#include <vector>
#include <memory>
#include "crypto.h"

#pragma comment(lib, "Crypt32.lib")

#ifdef _WIN64
#pragma warning(disable:4267)
#endif

#pragma region Crypto::CryptContext

Crypto::CryptContext::CryptContext(HCRYPTPROV hProv) noexcept
{
	this->hCryptProv = hProv;
}

Crypto::CryptContext::CryptContext(CryptContext && context)
{
	this->hCryptProv = NULL;
	//*this = std::move(context);
	this->operator=(std::move(context));
}

Crypto::CryptContext::CryptContext(const CryptContext & context)
{
	this->hCryptProv = NULL;
	//*this = context;
	this->operator=(context);
}

Crypto::CryptContext::~CryptContext()
{
	this->release();
}

void Crypto::CryptContext::operator=(const CryptContext & context)
{
	this->release();
	if (context.hCryptProv != NULL) {
		if (CryptContextAddRef(context.hCryptProv, NULL, 0))
			this->hCryptProv = context.hCryptProv;
	}
}

void Crypto::CryptContext::operator=(CryptContext && cxt)
{
	this->release();
	this->hCryptProv = cxt.hCryptProv;
	cxt.hCryptProv = NULL;
}

bool Crypto::CryptContext::acquire(DWORD dwProvType) noexcept
{
	this->release();
	if (!CryptAcquireContext(&hCryptProv, nullptr, nullptr, dwProvType, CRYPT_VERIFYCONTEXT))
		if (!CryptAcquireContext(&hCryptProv, nullptr, nullptr, dwProvType, CRYPT_VERIFYCONTEXT | CRYPT_NEWKEYSET))
			return false;//throw std::exception("Unable to obtain a cryptographic provider handle.");
	return true;
}

bool Crypto::CryptContext::delete_container(LPCTSTR container)
{
	HCRYPTPROV discard;
	if (CryptAcquireContext(&discard, container, nullptr, PROV_RSA_FULL, CRYPT_DELETEKEYSET))
		return true;
	return false;
}

void Crypto::CryptContext::release()
{
	if (hCryptProv)
		CryptReleaseContext(hCryptProv, 0);
	hCryptProv = NULL;
}

#pragma endregion

#pragma region Crypto::hash

Crypto::hash::hash(Algorithms algorithm, HCRYPTKEY hKey):hash(algorithm, CryptContext::static_acquire(PROV_RSA_AES), hKey) {}

Crypto::hash::hash(Algorithms algorithm, const CryptContext & context, HCRYPTKEY hKey) : context(context)
{
	hHash = NULL;
	switch (algorithm) {
	case sha256:
		if (!this->context.acquired() || !CryptCreateHash(this->context.handle(), CALG_SHA_256, 0, 0, &hHash))
			throw std::exception("CryptCreateHash() failed.");
		break;
	case sha384:
		if (!this->context.acquired() || !CryptCreateHash(this->context.handle(), CALG_SHA_384, 0, 0, &hHash))
			throw std::exception("CryptCreateHash() failed.");
		break;
	case sha512:
		if (!this->context.acquired() || !CryptCreateHash(this->context.handle(), CALG_SHA_512, 0, 0, &hHash))
			throw std::exception("CryptCreateHash() failed.");
		break;
	case md5:
		if (!this->context.acquired() || !CryptCreateHash(this->context.handle(), CALG_MD5, 0, 0, &hHash))
			throw std::exception("CryptCreateHash() failed.");
		break;
	case hmac:
		if (!this->context.acquired() || !CryptCreateHash(this->context.handle(), CALG_MD5, hKey, 0, &hHash))
			throw std::exception("CryptCreateHash() failed.");
		break;
	}
}

Crypto::hash::~hash()
{
	if (hHash)
		CryptDestroyHash(hHash);
}

std::vector<BYTE> Crypto::hash::sign_hash()
{
	/*
	** it works by sharing a CryptContext
	** once you import the rsa key, you can create a hash on that same handle
	** and when you use it to sign data, it will use the rsa public key that belongs to that context.
	** it's quite annoying..
	*/
	DWORD dwLen = NULL;
	if (CryptSignHash(hHash, AT_SIGNATURE, nullptr, 0, nullptr, &dwLen))
	{
		std::unique_ptr<BYTE> signature(new BYTE[dwLen]);
		if (CryptSignHash(hHash, AT_SIGNATURE, nullptr, 0, signature.get(), &dwLen))
		{
			std::vector<BYTE> data(signature.get(), signature.get() + dwLen);
			return data;
		}
	}
	return std::vector<BYTE>();
}

bool Crypto::hash::hash_data(LPCVOID data, DWORD dwDataLen)
{
	if (!available())
		return false;
	return ::CryptHashData(hHash, (const BYTE*)data, dwDataLen, NULL) == TRUE;
}

bool Crypto::hash::hash_key(HCRYPTKEY hSessionKey)
{
	if (!available())
		return false;
	return ::CryptHashSessionKey(hHash, hSessionKey, NULL) == TRUE; // https://msdn.microsoft.com/en-us/library/windows/desktop/aa380205(v=vs.85).aspx
}

DWORD Crypto::hash::get_hash_size()
{
	if (!available())
		return NULL;
	DWORD dwHashLen, dwLen = sizeof(dwHashLen);
	if (CryptGetHashParam(
		hHash,
		HP_HASHSIZE,
		(BYTE *)&dwHashLen,
		&dwLen,
		0))
		return dwHashLen;
	return NULL;
}

std::vector<BYTE> Crypto::hash::get_hash_bytes()
{
	if (!available())
		return std::vector<BYTE>();
	std::vector<BYTE> hash_bytes;
	DWORD hash_size;
	hash_bytes.resize(hash_size = get_hash_size());
	if (::CryptGetHashParam(hHash, HP_HASHVAL, &hash_bytes[0], &hash_size, 0) == TRUE)
		return hash_bytes;
	else
		return std::vector<BYTE>();
}

HCRYPTHASH Crypto::hash::duplicate()
{
	if (!available())
		return NULL;
	HCRYPTHASH hDuplicate;
	if (CryptDuplicateHash(hHash, NULL, 0, &hDuplicate))
		return hDuplicate;
	return NULL;
}

#pragma endregion

#pragma region Crypto::AES

Crypto::AES::AES()
{
	//maybe use the MS_ENH_RSA_AES_PROV provider?
	context.acquire(PROV_RSA_AES);
	dwBlockSize = NULL;
	hCryptKey = NULL;
}

Crypto::AES::AES(AES && other)//:context(std::move(other.context))
{
	hCryptKey = NULL;
	this->operator=(std::move(other));
}

Crypto::AES::AES(const AES & other)//:context(other.context)
{
	hCryptKey = NULL;
	this->operator=(other);
}

Crypto::AES::AES(const CryptContext & context) :context(context)
{
	dwBlockSize = NULL;
	hCryptKey = NULL;
}

Crypto::AES::AES(CryptContext && context) :context(std::move(context))
{
	dwBlockSize = NULL;
	hCryptKey = NULL;
}

Crypto::AES::~AES()
{
	this->release();
}

void Crypto::AES::operator=(AES && o)
{
	this->release();
	this->context = std::move(o.context);
	this->hCryptKey = o.hCryptKey;
	this->dwBlockSize = o.dwBlockSize;
	o.hCryptKey = NULL;
}

void Crypto::AES::operator=(const AES & other)
{
	this->release();
	context = other.context;
	hCryptKey = other.duplicate();
	this->dwBlockSize = other.dwBlockSize;
}

bool Crypto::AES::derive_key(Algorithms algorithm, const std::string& password)
{
	return derive_key(algorithm, std::vector<BYTE>(password.begin(), password.end()));
}

bool Crypto::AES::derive_key(Algorithms algorithm, const std::wstring& password)
{
	auto const data = reinterpret_cast<BYTE const *>(password.data());
	return derive_key(algorithm, std::vector<BYTE>(data, data + password.size() * sizeof(password.front())));
}

bool Crypto::AES::derive_key(Algorithms algorithm, const std::vector<BYTE>& password)
{
	if (!context.acquired())
		return false;
	this->release();
	hash hash(hash::sha512, context);
	if (!hash.hash_data(password.data(), password.size()))
		return false;
	DWORD dwAlgorithm = GetAlgID(algorithm);
	if (CryptDeriveKey(context.handle(), dwAlgorithm, hash.handle(), NULL, &hCryptKey)) {
		DWORD dwBlockLen = NULL, dwLen = sizeof(dwBlockLen);
		if (CryptGetKeyParam(hCryptKey, KP_BLOCKLEN, reinterpret_cast<BYTE*>(&dwBlockLen), &dwLen, 0)) {
			dwBlockLen /= 8;
			dwBlockSize = dwBlockLen;
		}
		else
			throw std::exception("Unable to get key block length");
		return true;
	}
	else
		return false;
}

bool Crypto::AES::generate_key(Algorithms algorithm)
{
	if (!context.acquired())
		return false;
	this->release();
	DWORD dwAlgorithm = GetAlgID(algorithm);
	if (!CryptGenKey(context.handle(), dwAlgorithm, CRYPT_EXPORTABLE, &hCryptKey))
		return false;
	DWORD dwBlockLen = NULL, dwLen = sizeof(dwBlockLen);
	if (CryptGetKeyParam(hCryptKey, KP_BLOCKLEN, reinterpret_cast<BYTE*>(&dwBlockLen), &dwLen, 0)) {
		dwBlockLen /= 8;
		dwBlockSize = dwBlockLen;
	}
	else
		throw std::exception("Unable to get key block length");
	return true;
}

bool Crypto::AES::Import(HCRYPTKEY hPubKey, const std::vector<BYTE>& data)
{
	this->release();
	if (!context.acquired())
		return false;
	if (::CryptImportKey(context.handle(), data.data(), data.size(), hPubKey, 0, &hCryptKey)) {
		DWORD dwBlockLen = NULL, dwLen = sizeof(dwBlockLen);
		if (!CryptGetKeyParam(hCryptKey, KP_BLOCKLEN, (PBYTE)&dwBlockLen, &dwLen, 0))
			return false;
		dwBlockLen /= 8;
		dwBlockSize = dwBlockLen;
		return true;
	}
	else
		return false;
}

std::vector<BYTE> Crypto::AES::Export(HCRYPTKEY hExpKey) const
{
	if (!hCryptKey || !hExpKey)
		throw std::exception("key export failed.");
	DWORD dwSize = NULL;
	if (::CryptExportKey(hCryptKey, hExpKey, SIMPLEBLOB, 0, nullptr, &dwSize)) {
		std::vector<BYTE> data;
		data.resize(dwSize);
		if (::CryptExportKey(hCryptKey, hExpKey, SIMPLEBLOB, 0, &data[0], &dwSize))
			return data;
	}
	throw std::exception("key export failed.");
}

bool Crypto::AES::encrypt(PBYTE pData, PDWORD lpdwDataLen, DWORD dwBufferLen)
{
	if (!hCryptKey)
		return false;
	return (CryptEncrypt(hCryptKey, NULL, TRUE, 0, pData, lpdwDataLen, dwBufferLen) == TRUE);
}

bool Crypto::AES::decrypt(PBYTE pData, PDWORD lpdwDataLen)
{
	if (!hCryptKey)
		return false;
	return (CryptDecrypt(hCryptKey, NULL, TRUE, 0, pData, lpdwDataLen) == TRUE);
}

std::vector<BYTE> Crypto::AES::encrypt(const std::vector<BYTE>& data)
{
	if (data.size() == 0)
		return std::vector<BYTE>();
	std::vector<BYTE> result(data);
	result.resize(this->get_plaintext_encrypted_len(data.size()));
	DWORD size = data.size();
	if (encrypt(result.data(), &size, result.size()))
		return result;
	else
		throw std::exception("Unable to encrypt data");
}

std::vector<BYTE> Crypto::AES::decrypt(const std::vector<BYTE>& data)
{
	if (data.size() == 0)
		return std::vector<BYTE>();
	std::vector<BYTE> result(data);
	DWORD dwSize = result.size();
	if (this->decrypt(result.data(), &dwSize)) {
		result.resize(dwSize);
		return result;
	}
	else
		throw std::exception("Unable to decrypt");
}

bool Crypto::AES::blockencrypt(PVOID pData, PDWORD lpdwDataLen, DWORD dwBufferLen)
{
	if (!pData || !lpdwDataLen || !available())
		return false;
	DWORD dwEncryptedLen = this->get_plaintext_encrypted_len(*lpdwDataLen);
	if (dwBufferLen < dwEncryptedLen)
		return false;
	int nBlocks = (*lpdwDataLen / dwBlockSize) + (*lpdwDataLen % dwBlockSize ? 1 : 0);
	BOOL bFinal = FALSE;
	for (int i = 0; i < nBlocks; i++) {
		bFinal = i + 1 == nBlocks;
		DWORD dwChunkLen = bFinal ? (*lpdwDataLen - (dwBlockSize * i)) : dwBlockSize;
		if (!CryptEncrypt(hCryptKey, NULL, bFinal, NULL, &PBYTE(pData)[i * dwBlockSize], &dwChunkLen, dwBufferLen - (i * dwBlockSize))) {
			return false;
		}
	}
	*lpdwDataLen = dwEncryptedLen;
	return true;
}

std::vector<BYTE> Crypto::AES::blockencrypt(LPCVOID pData, DWORD dwLen)
{
	if (!hCryptKey || !pData || !dwLen)
		throw std::exception("blockencrypt() unable to enecrypt: !hCryptKey || !pData || !dwLen");
	std::vector<BYTE> vec;
	vec.resize(this->get_plaintext_encrypted_len(dwLen));
	memcpy_s(vec.data(), vec.size(), pData, dwLen);
	if (this->blockencrypt(vec.data(), &dwLen, vec.size()))
		return vec;
	else
		throw std::exception("blockencrypt() failed.");
}

bool Crypto::AES::blockdecrypt(PVOID pData, PDWORD lpdwDataLen)
{
	if (!hCryptKey || !pData || !lpdwDataLen || !*lpdwDataLen)
		return false;
	int nBlocks = (*lpdwDataLen / dwBlockSize);
	BOOL bFinal = false;
	DWORD dwLen = NULL;
	for (int i = 0; i < nBlocks; i++) {
		bFinal = i + 1 == nBlocks;
		DWORD dwChunkLen = dwBlockSize;
		if (!CryptDecrypt(hCryptKey, NULL, bFinal, NULL, &reinterpret_cast<BYTE*>(pData)[i * dwBlockSize], &dwChunkLen))
			return false;
		dwLen += dwChunkLen;
	}
	*lpdwDataLen = dwLen;
	return true;
}

HCRYPTKEY Crypto::AES::duplicate() const
{
	if (!hCryptKey)
		return NULL;
	HCRYPTKEY hDuplicate;
	if (CryptDuplicateKey(hCryptKey, nullptr, NULL, &hDuplicate))
		return hDuplicate;
	return NULL;
}

void Crypto::AES::release()
{
	if (hCryptKey)
		::CryptDestroyKey(hCryptKey);
	hCryptKey = NULL;
	dwBlockSize = NULL;
}

DWORD Crypto::AES::GetAlgID(Algorithms alg)
{
	switch (alg) {
	case aes_128:
		return CALG_AES_128;
		break;
	case aes_192:
		return CALG_AES_192;
		break;
	case aes_256:
	default:
		return CALG_AES_256;
		break;
	}
}

#pragma endregion

#pragma region Crypto::RSA


Crypto::RSA::RSA()
{
	hKey = NULL;
	//I decided against PROV_RSA_FULL, as PROV_RSA_AES seems better.
	context.acquire(PROV_RSA_AES);
}

Crypto::RSA::RSA(RSA && other):context(std::move(other.context))
{
	this->hKey = other.hKey;
	other.hKey = NULL;
}

Crypto::RSA::RSA(const CryptContext & context) :context(context)
{
	hKey = NULL;
}

Crypto::RSA::RSA(CryptContext && context) : context(std::move(context))
{
	hKey = NULL;
}

Crypto::RSA::~RSA()
{
	this->release();
}

void Crypto::RSA::operator=(RSA && other)
{
	this->release();
	this->hKey = other.hKey;
	this->context = std::move(other.context);
	other.hKey = NULL;
}

bool Crypto::RSA::generate(Methods method, Algorithms key_size, DWORD dwFlags)
{
	if (!context.acquired())
		return false;
	this->release();
	//ALG_ID Algid = method == signature ? AT_SIGNATURE : AT_KEYEXCHANGE;
	ALG_ID Algid = method == signature ? CALG_RSA_SIGN : CALG_RSA_KEYX;
	if (CryptGenKey(context.handle(), Algid, key_size | dwFlags, &hKey))
		return true;
	else
		return false;
}

std::vector<BYTE> Crypto::RSA::export_private_key(const std::string & password)
{
	return export_private_key(std::vector<BYTE>(password.begin(), password.end()));
}

std::vector<BYTE> Crypto::RSA::export_private_key(const std::wstring & password)
{
	auto const data = reinterpret_cast<BYTE const *>(password.data());
	return export_private_key(std::vector<BYTE>(data, data + password.size() * sizeof(password.front())));
}

std::vector<BYTE> Crypto::RSA::export_private_key(const std::vector<BYTE>& password)
{
	if (!available())
		throw std::exception("RSA key N/A.");
	AES aes;
	if (!aes.derive_key(aes.aes_256, password))
		throw std::exception("Unable to derive key from password.");
	DWORD cbData = NULL;
	if (CryptExportKey(hKey, NULL, PRIVATEKEYBLOB, 0, nullptr, &cbData)) {
		//std::unique_ptr<BYTE> data(new BYTE[cbData]);
		std::vector<BYTE> data;
		data.resize(cbData);
		if (CryptExportKey(hKey, NULL, PRIVATEKEYBLOB, 0, data.data(), &cbData)) {
			return aes.encrypt(data);
		}
	}
	throw std::exception("Unable to export private key.");
}

std::vector<BYTE> Crypto::RSA::export_public_key()
{
	if (!available())
		throw std::exception("RSA key N/A.");
	DWORD cbData = NULL;
	if (CryptExportKey(hKey, NULL, PUBLICKEYBLOB, 0, nullptr, &cbData)) {
		std::vector<BYTE> data;
		data.resize(cbData);
		if (CryptExportKey(hKey, NULL, PUBLICKEYBLOB, 0, data.data(), &cbData)) {
			return data;
		}
	}
	throw std::exception("Unable to export public key.");
}

bool Crypto::RSA::import_private_key(const std::vector<BYTE>& data, const std::string & password)
{
	return import_private_key(data, std::vector<BYTE>(password.begin(), password.end()));
}

bool Crypto::RSA::import_private_key(const std::vector<BYTE>& data, const std::wstring & password)
{
	auto const pw = reinterpret_cast<BYTE const *>(password.data());
	return import_private_key(data, std::vector<BYTE>(pw, pw + password.size() * sizeof(password.front())));
}

bool Crypto::RSA::import_private_key(const std::vector<BYTE>& data, const std::vector<BYTE>& password)
{
	if (!context.acquired())
		return false;
	this->release();
	AES aes;
	if (!aes.derive_key(aes.aes_256, password))
		return false;
	auto vec = aes.decrypt(data);
	return CryptImportKey(context.handle(), vec.data(), vec.size(), NULL, 0, &hKey) == TRUE; //return CryptImportKey(hCryptProv, data->pbData, data->cbData, aes.get(), 0, &hCryptKey) == TRUE;
}

bool Crypto::RSA::import_public_key(const std::vector<BYTE>& data)
{
	if (!context.acquired())
		return false;
	this->release();
	//_size = data->cbData - 20;
	return CryptImportKey(context.handle(), data.data(), data.size(), NULL, 0, &hKey) == TRUE;
}

bool Crypto::RSA::encrypt(PBYTE pData, PDWORD lpdwDataLen, DWORD dwBufferLen)
{
	if (hKey == NULL)
		return false;
	return (CryptEncrypt(hKey, NULL, TRUE, 0, pData, lpdwDataLen, dwBufferLen) == TRUE);
}

bool Crypto::RSA::decrypt(PBYTE pData, PDWORD lpdwDataLen)
{
	if (hKey == NULL)
		return false;
	return (CryptDecrypt(hKey, NULL, TRUE, 0, pData, lpdwDataLen) == TRUE);
}

void Crypto::RSA::release()
{
	if (hKey)
		CryptDestroyKey(hKey);
	hKey = NULL;
}

std::vector<BYTE> Crypto::RSA::sign_data(const std::vector<BYTE>& data)
{
	if (!available())
		throw std::exception("RSA key N/A");
	hash hash(hash::Algorithms::sha512, context);
	if (!hash.available() || !hash.hash_data(data.data(), data.size()))
		throw std::exception("Unable to hash data/!v");
	return hash.sign_hash();
}

std::vector<BYTE> Crypto::RSA::sign_key(HCRYPTKEY key)
{
	if (!available())
		throw std::exception("RSA key N/A");
	hash hash(hash::Algorithms::sha512, context);
	if (!hash.available() || !hash.hash_key(key))
		throw std::exception("Unable to hash data/!v");
	return hash.sign_hash();
}

bool Crypto::RSA::verify_data(const std::vector<BYTE>& data, const std::vector<BYTE>& signature)
{
	if (!available())
		throw std::exception("RSA key N/A");
	hash hash(hash::Algorithms::sha512, context);
	if (!hash.available() || !hash.hash_data(data.data(), data.size()))
		throw std::exception("Unable to hash data/!v");
	return CryptVerifySignature(hash.handle(), signature.data(), signature.size(), hKey, nullptr, 0) == TRUE;
}

bool Crypto::RSA::verify_key(HCRYPTKEY hCryptKey, const std::vector<BYTE>& signature) //theoretical, haven't tested it yet but it should work.
{
	if (!available())
		throw std::exception("RSA key N/A");
	hash hash(hash::Algorithms::sha512, context);
	if (!hash.available() || !hash.hash_key(hCryptKey))
		throw std::exception("Unable to hash data/!v");
	return CryptVerifySignature(hash.handle(), signature.data(), signature.size(), hKey, nullptr, 0) == TRUE;
}

#pragma endregion

#pragma region Crypto::Random

Crypto::Random::Random() noexcept
{
	context.acquire(PROV_RSA_AES);
}

Crypto::Random::Random(const CryptContext & context) :context(context)
{

}

bool Crypto::Random::Generate(LPVOID pMemory, DWORD dwSize)
{
	SecureZeroMemory(pMemory, dwSize);
	return ::CryptGenRandom(context.handle(), dwSize, (BYTE*)pMemory) == TRUE;
}

#pragma endregion


#ifdef _WIN64
#pragma warning(default:4267)
#endif
#define WIN32_LEAN_AND_MEAN
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <wincrypt.h>
#include <Windows.h>
#include <utility>
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <map>
#include <crypto.h>
#include <sockets/tcp/sync/socket.h>

#pragma comment(lib, "Ws2_32.lib")

#pragma region sockets::tcp::sync::socket_verification

bool sockets::tcp::sync::socket_verification::verify(SOCKET sSocket)
{
	std::lock_guard<std::mutex> lock(m);
	auto entry = sockets.find(sSocket);
	if (entry != sockets.end()) {
		entry->second = true;
		return true;
	}
	else
		return false;
}

bool sockets::tcp::sync::socket_verification::request(SOCKET sSocket)
{
	if (sSocket == INVALID_SOCKET)
		return false;
	std::unique_lock<std::mutex> lock(m);
	if (sockets.find(sSocket) != sockets.end())
		return false;
	sockets[sSocket] = false; //auto it = sockets.insert(std::pair<SOCKET, bool>(sSocket, false)); //returns iterator
	lock.unlock();
	bool bSuccess = false;
	std::chrono::system_clock::time_point e = std::chrono::system_clock::now() + std::chrono::seconds(25);
	while (!bSuccess && std::chrono::system_clock::now() <= e) {
		std::this_thread::sleep_for(std::chrono::milliseconds(5));
		bSuccess = is_verified(sSocket);
	}
	lock.lock();
	bSuccess = sockets[sSocket];
	sockets.erase(sSocket);
	return bSuccess;
}

bool sockets::tcp::sync::socket_verification::is_verified(SOCKET sSocket)
{
	std::lock_guard<std::mutex> lock(m);
	return sockets[sSocket];
}

sockets::tcp::sync::socket_verification sockets::tcp::sync::verify_sock;

#pragma endregion


namespace sockets {

	namespace tcp {
#pragma region synchronous sockets
		namespace sync {
			listener::listener()
			{
				bDisconnected = false;
				iSockets = NULL;
				for (int i = 0; i < 2; i++)
					IPStatus[i] = false;
			}

			listener::listener(listener && other) :listener()
			{
				this->operator=(std::move(other));
			}

			listener::~listener()
			{
				this->close();
			}

			void listener::operator=(listener && other)
			{
				this->close();
				this->bDisconnected = other.bDisconnected;
				for (int i = 0; i < other.iSockets; i++)
					this->sSockets[i] = other.sSockets[i];
				this->iSockets = other.iSockets;
				for (int i = 0; i < 2; i++)
					IPStatus[i] = other.IPStatus[i];
				other.iSockets = NULL;
				other.bDisconnected = true;
			}

			void listener::close()
			{
				for (int i = 0; i < iSockets; i++)
					::closesocket(sSockets[i]);
				iSockets = NULL;
				this->bDisconnected = true;
				for (int i = 0; i < 2; i++)
					IPStatus[i] = false;
			}

			bool listener::listen(WORD wPort, listener_flags flags)
			{
				this->close();
				this->wPort = wPort;
				struct addrinfo *result = nullptr, *ptr = nullptr, hints;
				ZeroMemory(&hints, sizeof(hints));
				if ((flags & IPv4) > 0 && (flags & IPv6) > 0)
					hints.ai_family = AF_UNSPEC;
				else if (flags & IPv4)
					hints.ai_family = AF_INET;
				else if (flags & IPv6)
					hints.ai_family = AF_INET6;
				else
					hints.ai_family = AF_UNSPEC;

				hints.ai_socktype = SOCK_STREAM;
				hints.ai_protocol = IPPROTO_TCP;
				hints.ai_flags = AI_PASSIVE;
				char port[6];
				sprintf_s(port, "%d", wPort);
				if (getaddrinfo(nullptr, port, &hints, &result) == ERROR_SUCCESS) {
					for (ptr = result; ptr != nullptr; ptr = ptr->ai_next) {
						if (ptr->ai_protocol != IPPROTO_TCP)
							continue;
						if (flags & listener_flags::LOOPBACK) {
							switch (ptr->ai_family) {
							case AF_INET:
								InetPton(AF_INET, TEXT("127.0.0.1"), &reinterpret_cast<SOCKADDR_IN*>(ptr->ai_addr)->sin_addr); //INADDR_LOOPBACK
								break;
							case AF_INET6:
							{
								InetPton(AF_INET6, TEXT("::1"), &reinterpret_cast<SOCKADDR_IN6*>(ptr->ai_addr)->sin6_addr);
							}
							break;
							}
						}

						sSockets[iSockets] = ::socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
						if (sSockets[iSockets] == INVALID_SOCKET)
							continue;
						if (::bind(sSockets[iSockets], ptr->ai_addr, static_cast<int>(ptr->ai_addrlen)) == SOCKET_ERROR) {
							::closesocket(sSockets[iSockets]);
							continue;
						}
						if (::listen(sSockets[iSockets], SOMAXCONN) == SOCKET_ERROR) {
							::closesocket(sSockets[iSockets]);
							continue;
						}
						switch (ptr->ai_family) {
						case AF_INET:
							IPStatus[ipv4] = true;
							break;
						case AF_INET6:
							IPStatus[ipv6] = true;
							break;
						}
						iSockets++;
					}
					freeaddrinfo(result);
					return !(bDisconnected = iSockets == NULL);
				}
				else
					return false;
			}

			SOCKET listener::accept(int iTimeout, LPSOCKADDR addr, int * size)
			{
				TIMEVAL t;
				t.tv_sec = (iTimeout / 1000);
				t.tv_usec = (iTimeout % 1000) * 1000;
				FD_SET set;
				FD_ZERO(&set);
				for (int i = 0; i < iSockets; i++) {
					FD_SET(sSockets[i], &set);
				}
				int i;
				if ((i = select(0, &set, nullptr, nullptr, &t)) > 0) {
					SOCKADDR_STORAGE discard;
					int idummy = sizeof(discard);
					if (addr == nullptr) {
						addr = reinterpret_cast<LPSOCKADDR>(&discard);
						size = &idummy;
					}
					return ::accept(set.fd_array[0], addr, size);
				}
				else if (i == SOCKET_ERROR) //returns 0 if timed out, -1 means an error occured.
					this->close();
				return INVALID_SOCKET;
			}

			socket::socket(SOCKET sSocket) :encryption(Crypto::CryptContext())
			{
				this->set_IO_Timeout(DEFAULT_SOCKET_TIMEOUT);
				this->set_string_length_limit(DEFAULT_MAXIMUM_STRING_LENGTH);
				FD_ZERO(&set);
				bDisconnected = (this->sSock = sSocket) == INVALID_SOCKET;
				if (sSock != INVALID_SOCKET)
					FD_SET(sSock, &set);
				if (!bDisconnected) {
					//check socket to ensure it's valid.
					int iError, iErrorLen = sizeof(iError);
					if (::getsockopt(sSock, SOL_SOCKET, SO_ERROR, reinterpret_cast<PCHAR>(&iError), &iErrorLen) == SOCKET_ERROR)
						bDisconnected = true;
					else
						bDisconnected = (iError == SOCKET_ERROR);
				}
			}

			void socket::operator=(socket && other)
			{
				this->disconnect();
				this->encryption = std::move(other.encryption);
				this->timeout = other.timeout;
				this->sSock = other.sSock;
				this->bDisconnected = other.bDisconnected;
				this->set = other.set;
				this->string_length_limit = other.string_length_limit;
				other.sSock = INVALID_SOCKET;
			}

			bool socket::connect(const sockaddr * addr, int addrlen, int timeout)
			{
				this->disconnect();
				SOCKET sTmp = ::socket(addr->sa_family, SOCK_STREAM, IPPROTO_TCP);
				if (sTmp == INVALID_SOCKET)
					return false;
				if (timeout == -1) { //connect via blocking mode
					if (::connect(sTmp, addr, addrlen) != SOCKET_ERROR) {
						sSock = sTmp;
						FD_SET(sSock, &set);
						bDisconnected = false;
						return true;
					}
				}
				else { //non-blocking connect will allow us to use a timeout by using select() to check if the socket is writable.
					TIMEVAL connect_timeout;
					connect_timeout.tv_sec = timeout / 1000;
					connect_timeout.tv_usec = (timeout % 1000) * 1000;
					u_long mode = 1;  //enable non-blocking mode on the socket
					ioctlsocket(sTmp, FIONBIO, &mode);
					if (::connect(sTmp, addr, addrlen) == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) {
						FD_SET w;
						FD_ZERO(&w);
						FD_SET(sTmp, &w);
						if (select(0, nullptr, &w, nullptr, &connect_timeout) == 1) {
							mode = 0;
							ioctlsocket(sTmp, FIONBIO, &mode); //disable non-blocking mode
							sSock = sTmp;
							FD_SET(sSock, &set);
							bDisconnected = false;
							return true;
						}
					}
				}
				::closesocket(sTmp);
				return false;
			}

			bool socket::connect(const std::string & host, WORD wPort, int timeout, int max_attempts)
			{
				char sPort[6];
				sprintf_s(sPort, "%d", wPort);
				ADDRINFO hints = {}, *padrinfo, *AI;
				hints.ai_family = AF_UNSPEC;
				hints.ai_socktype = SOCK_STREAM;
				hints.ai_protocol = IPPROTO_TCP;
				if (getaddrinfo(host.c_str(), sPort, &hints, &padrinfo) != 0)
					return false;
				//maximum 5 attempts to try and connect to the peer
				int nTries;
				for (AI = padrinfo, nTries = 0; AI != nullptr && nTries < max_attempts; AI = AI->ai_next, nTries++) {
					if (this->connect(AI->ai_addr, static_cast<int>(AI->ai_addrlen), timeout)) {
						freeaddrinfo(padrinfo);
						return true;
					}
				}
				freeaddrinfo(padrinfo);
				return false;
			}

			bool socket::send(LPCVOID data, int len)
			{
				if (bDisconnected)
					return false;
				if (data == nullptr || len == NULL)
					return len == NULL;
				if (encryption.available()) {
					auto cryptolen = encryption.get_plaintext_encrypted_len(len);
					auto buffer = std::unique_ptr<BYTE>(new BYTE[cryptolen]);
					if (!buffer)
#ifdef DEBUGGING
						throw std::runtime_error("Out of memory: " + std::string(__FILE__) + ":" + std::to_string(__LINE__));
#else
						throw std::exception("Out of memory");
#endif
					memcpy_s(buffer.get(), cryptolen, data, len);
					DWORD dwLen = len;
					if (encryption.encrypt((PBYTE)buffer.get(), &dwLen, cryptolen)) {
						if (!this->internal_send(buffer.get(), dwLen)) {
							this->disconnect();
							return false;
						}
					}
					else
#ifdef DEBUGGING
						throw std::runtime_error("Unable to encrypt data: " + std::string(__FILE__) + ":" + std::to_string(__LINE__));
#else
						throw std::exception("Unable to encrypt data");
#endif
				}
				else {
					if (!this->internal_send(data, len)) {
						this->disconnect();
						return false;
					}
				}
				return true;
			}

			bool socket::recv(LPVOID data, int len)
			{
				if (bDisconnected)
					return false;
				if (data == nullptr || len == NULL)
					return len == NULL;
				if (encryption.available()) {
					auto clen = encryption.get_plaintext_encrypted_len(len);
					auto buffer = std::unique_ptr<BYTE>(new BYTE[clen]); //I think it will throw a std::bad_alloc if it fails.
					//if (buffer.get() == nullptr) throw std::runtime_error("Out of memory: " + std::string(__FILE__) + ":" + std::to_string(__LINE__));

					if (!this->internal_recv(buffer.get(), clen)) {
						this->disconnect();
						return false;
					}
					if (encryption.decrypt((PBYTE)buffer.get(), &clen)) {
						if (clen != len) {
							this->disconnect(); //mismatching decrypted data length
							return false;
						}
						memcpy_s(data, len, buffer.get(), clen);
					}
					else
#ifdef DEBUGGING
						throw std::runtime_error("Unable to decrypt data: " + std::string(__FILE__) + ":" + std::to_string(__LINE__));
#else
						throw std::exception("Unable to decrypt data");
#endif
				}
				else {
					if (!this->internal_recv(data, len)) {
						this->disconnect();
						return false;
					}
				}
				return true;
			}

#ifdef QT_CORE_LIB
			bool socket::sendstring(const QString& str)
			{
				this->send<unsigned int>(str.length());
				return send(str.data(), str.length() * sizeof(wchar_t));
			}
#endif

			bool socket::sendstring(const std::string & s)
			{
				if (s.length() > maximum_string_length())
#ifdef DEBUGGING
					throw std::exception("sendstring() failed - len > string length limit.");
#else
					throw std::exception("");
#endif
					
				this->send<unsigned int>(static_cast<unsigned int>(s.length()));
				return this->send(s.data(), static_cast<int>(s.length() * sizeof(char)));
			}
			
			bool socket::sendstring(const std::wstring & ws)
			{
				if (ws.length() > maximum_string_length())
#ifdef DEBUGGING
					throw std::exception("sendstring() failed - len > string length limit.");
#else
					throw std::exception("");
#endif
				this->send<unsigned int>(static_cast<unsigned int>(ws.length()));
				return this->send(ws.data(), static_cast<int>(ws.length() * sizeof(wchar_t)));
			}

			bool socket::enable_encryption_s(Crypto::AES::Algorithms alg)
			{
				if (encryption.available())
					return true;
				Crypto::CryptContext context;
				if (!context.acquire(PROV_RSA_AES)) {
					this->send<bool>(false);
					return false;
				}
				Crypto::RSA rsa(context);
				Crypto::AES aes(context);
				if (!aes.generate_key(alg)) {
					this->send<bool>(false);
					return false;
				}
				this->send<bool>(true);
				if (!this->recv<bool>()) //either it was unable to generate the rsa exchange key, or it was unable to export the public key.
					return false;
				std::vector<BYTE> rsa_public_key;
				WORD wLen = this->recv<WORD>();
				if (wLen > 2048 + 100) { //check if the rsa key len is too large. Maximum key size = 16384 bits(2,048 bytes), not sure if there's padding so I add + 100.
					this->disconnect();
					return false;
				}
				rsa_public_key.resize(wLen);
				if (!this->recv(&rsa_public_key[0], static_cast<int>(rsa_public_key.size())))
					return false;
				if (!rsa.import_public_key(rsa_public_key)) {
					this->send<bool>(false);
					return false;
				}
				try {
					auto data = aes.Export(rsa.get());
					this->send<bool>(true);
					this->send<WORD>(static_cast<WORD>(data.size()));
					this->send(data.data(), static_cast<int>(data.size()));
					if (this->recv<bool>()) {
						encryption = std::move(aes);
						return true;
					}
					else
						return false;
				}
				catch (std::exception&) {
					this->send<bool>(false);
					return false;
				}
			}

			bool socket::enable_encryption_c(Crypto::RSA::Algorithms transportation_algorithm)
			{
				if (encryption.available())
					return true;
				if (this->recv<bool>() == false) //was it unable to acquire context/generate aes key?
					return false;
				Crypto::CryptContext context;
				if (!context.acquire(PROV_RSA_AES)) {
					this->send<bool>(false);
					return false;
				}
				Crypto::RSA rsa(context);
				if (!rsa.generate(Crypto::RSA::Methods::encryption, transportation_algorithm)) {
					this->send<bool>(false);
					return false;
				}
				std::vector<BYTE> rsa_public_key;
				try {
					rsa_public_key = rsa.export_public_key();
				}
				catch (std::exception&) {
					this->send<bool>(false);
					return false;
				}
				this->send<bool>(true);
				this->send<WORD>(static_cast<WORD>(rsa_public_key.size()));
				this->send(rsa_public_key.data(), static_cast<int>(rsa_public_key.size()));
				if (!this->recv<bool>())
					return false;
				std::vector<BYTE> enc_key;
				WORD wLen = this->recv<WORD>();
				if (wLen > 2048 + 100) {
					this->disconnect();
					return false;
				}
				enc_key.resize(wLen);
				if (!this->recv(enc_key.data(), static_cast<int>(enc_key.size())))
					return false;

				Crypto::AES aes(context);
				bool bImported = aes.Import(rsa.get(), enc_key);
				this->send<bool>(bImported);
				if (bImported && connected()) {
					encryption = std::move(aes);
					return true;
				}
				return false;
			}

			SOCKET socket::create_reverse_socket_s()
			{
				SOCKET sLocal = this->recv<SOCKET>();
				if (sLocal == INVALID_SOCKET || !this->connected())
					return INVALID_SOCKET;
				ULONGLONG ullTick = GetTickCount64();
				while (GetTickCount64() - ullTick < 1000) { //because request() is only called after we send the socket to peer, it might not be added yet(this will usually only occur on localhost, as the remote peer sends it back to us to be verified).
					if (verify_sock.verify(sLocal)) {
						this->send<bool>(true);
						return sLocal;
					}
					Sleep(10);
				}
				this->send<bool>(false);
				return INVALID_SOCKET;
			}

			SOCKET socket::create_reverse_socket_c()
			{
				sockaddr_storage addr;
				int len = sizeof(addr);
				if (::getpeername(sSock, (LPSOCKADDR)&addr, &len) == 0) {
					socket tmp;
					if (tmp.connect((LPSOCKADDR)&addr, len, 20000)) {
						tmp.initiate(id_reverse_socket);
						SOCKET sRemote = tmp.recv<SOCKET>();
						if (!tmp.connected())
							sRemote = INVALID_SOCKET;
						this->send<SOCKET>(sRemote);
						if (sRemote == INVALID_SOCKET || false == this->recv<bool>()) //was the socket verified?
							return INVALID_SOCKET;
						return tmp.acquire_raw_socket();
					}
				}
				this->send<SOCKET>(INVALID_SOCKET);
				return INVALID_SOCKET;
			}

			void socket::initiate(connection_types type)
			{
				this->send<BYTE>(type);
			}

			connection_types socket::initiate()
			{
				switch (this->recv<BYTE>()) {
				case id_reverse_socket:
				{
					this->send<SOCKET>(sSock);
					if (verify_sock.request(sSock))
						this->invalidate_socket();
					return id_reverse_socket;
				}
				break;
				case connection_types::id_client:
					return connection_types::id_client;
					break;
				default:
					return connection_types::id_unknown;
				}
			}

			void socket::disconnect()
			{
				if (sSock != INVALID_SOCKET) {
					::shutdown(sSock, SD_BOTH);
					::closesocket(sSock);
				}
				sSock = INVALID_SOCKET;
				FD_ZERO(&set);
				encryption.release();
				bDisconnected = true;
			}

			void socket::set_IO_Timeout(DWORD dwTimeout)
			{
				timeout.tv_sec = dwTimeout / 1000;
				timeout.tv_usec = (dwTimeout % 1000) * 1000;
			}

			std::string socket::ip()
			{
				SOCKADDR_STORAGE addr;
				int addrlen = sizeof(addr);
				if (sSock != INVALID_SOCKET && getpeername(sSock, reinterpret_cast<sockaddr*>(&addr), &addrlen) == 0) {
					char buf[NI_MAXHOST];//46 + 1
					inet_ntop(addr.ss_family, addr.ss_family == AF_INET ?
						PVOID(&reinterpret_cast<LPSOCKADDR_IN>(&addr)->sin_addr) :
						PVOID(&reinterpret_cast<LPSOCKADDR_IN6>(&addr)->sin6_addr), buf, sizeof(buf));
					return buf;
				}
				return "";
			}

			bool socket::internal_send(LPCVOID pMemory, size_t len)
			{
				size_t sent = 0;
				while (len) {
					if (select(0, nullptr, &set, nullptr, &timeout) == 1) {
						int i = ::send(sSock, &reinterpret_cast<const char*>(pMemory)[sent], static_cast<int>(len), 0);
						if (i <= 0)
							return false;
						len -= i;
						sent += i;
					}
					else
						return false;
				}
				return true;
			}

			bool socket::internal_recv(PVOID pMemory, size_t len)
			{
				size_t received = 0;
				while (len) {
					if (select(0, &set, nullptr, nullptr, &timeout) == 1) {
						int i = ::recv(sSock, &reinterpret_cast<char*>(pMemory)[received], static_cast<int>(len), 0);
						if (i <= 0)
							return false;
						len -= i;
						received += i;
					}
					else//0(timeout) or SOCKET_ERROR
						return false;
				}
				return true;
			}

		};
#pragma endregion
	};
};
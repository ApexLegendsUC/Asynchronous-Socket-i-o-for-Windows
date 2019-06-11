#pragma once
/*
	minimum dependency requirements:
	#define WIN32_LEAN_AND_MEAN
	#include <WinSock2.h>
	#include <WS2tcpip.h>
	#include <Windows.h>
	#include <wincrypt.h>
	#include <utility> //or #include <iostream>
*/
#include <bitflg.hpp>
#ifdef QT_CORE_LIB
#include <qstring.h>
#endif

namespace sockets {
#ifndef DEFAULT_SOCKET_TIMEOUT
#define DEFAULT_SOCKET_TIMEOUT 60 * 1000
#endif

#ifndef DEFAULT_MAXIMUM_STRING_LENGTH
#define DEFAULT_MAXIMUM_STRING_LENGTH 100 * 1024 //default size a string can be, -> 100KiB (ascii), -> 200KiB(unicode)
#endif

#if !defined(SOCKET_INITIALIZATION_ROUTINES)
#define SOCKET_INITIALIZATION_ROUTINES
	enum internet_protocols { ipv4, ipv6 };
	bool _inline initialize()
	{
		WSADATA wsa;
		int iWSAError, nTries = 0;
		while ((iWSAError = WSAStartup(MAKEWORD(2, 2), &wsa)) != 0 && nTries++ < 5) {
			switch (iWSAError) {
			case WSASYSNOTREADY:
			case WSAEPROCLIM:
				Sleep(5000);
				break;
			default: //WSAVERNOTSUPPORTED, WSAEFAULT, WSAVERNOTSUPPORTED, WSAEINPROGRESS
				Sleep(1000);
			}
		}
		return iWSAError == 0;
	};

	void _inline uninitialize()
	{
		::WSACleanup(); //return ::WSACleanup() == 0;
	};
#endif

	namespace tcp {

		namespace sync {

			enum listener_flags {
				LOOPBACK = BitFlags::option1,
				ANY = BitFlags::option2,
				IPv4 = BitFlags::option3,
				IPv6 = BitFlags::option4
			};
			listener_flags _inline operator |(const listener_flags& first, const listener_flags& other) {
				return static_cast<listener_flags>(static_cast<DWORD>(first) | static_cast<DWORD>(other));
			};

			class listener {
			public:
				listener();
				listener(listener&& other);
				listener(const listener&) = delete;
				~listener();
				void operator=(listener&& other);
				void operator=(const listener&) = delete;
				WORD port() const { return wPort; };
				bool connected() const { return !bDisconnected; };
				void close();
				bool status(internet_protocols protocol) const { return IPStatus[protocol]; };
				SOCKET accept(int iTimeout = 250, LPSOCKADDR addr = nullptr, int* size = nullptr);
				bool listen(WORD wPort, listener_flags flags = ANY | IPv4);
			private:
				bool bDisconnected;
				bool IPStatus[2];
				int iSockets;
				WORD wPort;
				SOCKET sSockets[FD_SETSIZE];
			};

			enum connection_types :BYTE {
				id_client = 0xBF,
				id_reverse_socket,
				id_unknown = 0
			};

			class socket_verification {
			public:
				bool verify(SOCKET sSocket);
				bool request(SOCKET sSocket);
			private:
				bool is_verified(SOCKET sSocket);
				std::mutex m;
				std::map<SOCKET, bool> sockets;
			}extern verify_sock;


			class socket {
			public:
				socket(SOCKET sSocket);
				socket() :socket(INVALID_SOCKET) {};
				socket(socket&& other) :socket() { *this = std::move(other); }; //this->operator=(std::move(other)); 
				socket(const socket&) = delete;
				~socket() { this->disconnect(); };
				void operator=(socket&& other);
				void operator=(const socket&) = delete;
				//WARNING: encryption will carry over to the new socket connection.
				bool connect(const sockaddr* addr, int addrlen, int timeout = -1);
				bool connect(const std::string& host, WORD wPort, int timeout = -1, int max_attempts = 5);
				bool send(LPCVOID data, int len);
				bool recv(LPVOID data, int len);
				template <typename T>
				bool send(const T& data);
				template <typename T>
				bool recv(T& data);
				template <typename T>
				T recv();
				template <typename T>
				T recvstring();
				bool sendstring(const std::string& s);
				bool sendstring(const std::wstring& ws);

#ifdef QT_CORE_LIB
				bool sendstring(const QString& str);
#endif
				void set_string_length_limit(size_t limit) { string_length_limit = limit; }; //limits the maximum size(in characters) a string can be received(or sent)
				size_t maximum_string_length() const { return string_length_limit; };
				

				bool enable_encryption_s(Crypto::AES::Algorithms alg = Crypto::AES::aes_256);
				bool enable_encryption_c(Crypto::RSA::Algorithms transportation = Crypto::RSA::rsa_2048);

				SOCKET create_reverse_socket_s();  //only works for properly configured synchronous socket i/o services.
				SOCKET create_reverse_socket_c();  //only works for properly configured synchronous socket i/o services.

				void initiate(connection_types type);
				connection_types initiate();
				void disconnect();
				bool connected() { return !bDisconnected; };
				void set_IO_Timeout(DWORD dwTimeout);
				SOCKET raw_socket() const { return sSock; };
				void invalidate_socket() { bDisconnected = true; sSock = INVALID_SOCKET; };
				SOCKET acquire_raw_socket() { SOCKET s = sSock; invalidate_socket(); return s; };
				bool encrypted() { return encryption.available(); };
				void disable_encryption() { encryption.release(); };
				void set_encryption(const Crypto::AES& enc) { encryption = enc; };
				Crypto::AES& get_encryption() { return encryption; };

				std::string ip();
			private:
				bool internal_send(LPCVOID pMemory, size_t len);
				bool internal_recv(PVOID pMemory, size_t len);
				SOCKET sSock;
				size_t string_length_limit;
				bool bDisconnected;
				TIMEVAL timeout;
				FD_SET set;
				Crypto::AES encryption;
			};

			template<typename T>
			inline bool socket::send(const T& data)
			{
				return this->send(&data, sizeof(data));
			}

			template<typename T>
			inline bool socket::recv(T & data)
			{
				return this->recv(&data, sizeof(data));
			}

			template<typename T>
			inline T socket::recv()
			{
				T tmp;
				if (this->recv(&tmp, sizeof(T)))
					return tmp;
				return T(); //throw std::exception("Unable to receive data.");
			}

			template<>
			inline bool socket::send(const std::string& data)
			{
				return this->sendstring(data);
			}

			template<>
			inline bool socket::send(const std::wstring& data)
			{
				return this->sendstring(data);
			}	
		
			template<>
			inline std::string socket::recvstring()
			{
				size_t len = this->recv<unsigned int>(); //warning: size_t differs on x86(4 bytes) / x64(8 bytes).
				if (len > maximum_string_length())
					throw std::exception("recvstring() failed - len > string length limit.");
				std::string s;
				s.resize(len);
				if (this->recv(&s[0], static_cast<int>(s.length() * sizeof(char))))
					return s;
				return "";
			}

			template<>
			inline std::wstring socket::recvstring()
			{
				auto len = this->recv<unsigned int>(); //stopped using size_t because if you compile an x86 and x64 binary, the sizes will be different.
				if (len > maximum_string_length())
					throw std::exception("recvstring() failed - len > string length limit.");
				std::wstring s;
				s.resize(len);
				if (this->recv(&s[0], static_cast<int>(s.length() * sizeof(wchar_t)))) //sizeof std::wstring::traits_type::char_type
					return s;
				return L"";
			}

			//this code has to be after the recvstring explicit templates otherwise it will result in a compiler error:

			template<>
			inline std::string socket::recv()
			{
				return recvstring<std::string>();
			}

			template<>
			inline std::wstring socket::recv()
			{
				return recvstring<std::wstring>();
			}

#ifdef QT_CORE_LIB
			template<>
			inline bool socket::send(const QString& data)
			{
				return this->sendstring(data);
			}
			
			template<>
			inline QString socket::recvstring()
			{
				//QString::fromWCharArray, QString::fromLocal8Bit if using raw strings(char*, wchar_t*).
				return QString::fromStdWString(recvstring<std::wstring>());
				/*if (bUnicode)
					return QString::fromStdWString(recvstring<std::wstring>());
				else
					return QString::fromStdString(recvstring<std::string>());
				*/
			}

			template<>
			inline QString socket::recv()
			{
				return recvstring<QString>();
			}
#endif

		}
	}
}
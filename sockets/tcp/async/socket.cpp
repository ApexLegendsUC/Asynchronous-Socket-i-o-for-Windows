#define WIN32_LEAN_AND_MEAN
//#define FD_SETSIZE 300 //32767
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <wincrypt.h>
#include <memory>
#include <vector>
#include <list>
#include <map>
#include <functional>
#include <string>
#include <future>
#include <crypto.h>
#include "socket.h"

#ifdef DEBUGGING
#include <iostream>
#endif

#pragma comment(lib, "Ws2_32.lib")

using namespace std;

using namespace std::chrono_literals;

namespace sockets {

	namespace tcp {
		namespace async {
#pragma pack(push, 1)
			struct sSerializedNetworkBufferHdr {
				bool bEncryptionEnabled;
				ULONGLONG buffer_size, name_size;
			};
#pragma pack(pop)

			socket::socket(io_service & io_service, SOCKET s) :handler(io_service)
			{
				this->init_bandwidth_cap();
				ullVirtuallyEnforcedSleep_rd = ullVirtuallyEnforcedSleep_wr = 0;
				this->io.io_block = io_block_none;
				this->keepalive.timeout = 60s;
				this->sSocket = s;
				this->keepalive.fired_hearbeat_packet = false;
				this->socket_state = sSocket == INVALID_SOCKET ? socket_states::disconnected : socket_states::connected;

				this->bDisconnectOnWritesCompleted = false;
				SOCKADDR_STORAGE addr;
				int addrlen = sizeof(addr);
				if (getpeername(sSocket, reinterpret_cast<sockaddr*>(&addr), &addrlen) == 0) {
					char buf[NI_MAXHOST];//46 + 1
					inet_ntop(addr.ss_family, addr.ss_family == AF_INET ?
						PVOID(&reinterpret_cast<LPSOCKADDR_IN>(&addr)->sin_addr) :
						PVOID(&reinterpret_cast<LPSOCKADDR_IN6>(&addr)->sin6_addr), buf, sizeof(buf));
					connection._ip = buf;
					connection.remote_port = ntohs(addr.ss_family == AF_INET ? reinterpret_cast<LPSOCKADDR_IN>(&addr)->sin_port : reinterpret_cast<LPSOCKADDR_IN6>(&addr)->sin6_port);
				}
				else
					connection.remote_port = 0;
				this->setup_heartbeat_callbacks();
			}

			socket::socket(io_service & svc, socket && other) :handler(svc)
			{
				this->init_bandwidth_cap();
				auto lock = other.handler.acquire_sockets_lock();
				std::lock_guard<std::recursive_mutex> lock2(other.io.m);
				this->io.io_block = other.io.io_block;
				this->ullVirtuallyEnforcedSleep_rd = this->ullVirtuallyEnforcedSleep_wr = 0;
				for (int i = 0; i < 2; i++) //a "light" move, we only take the limit.
					this->bandwidth_cap[i]->throttle(other.bandwidth_cap[i]->max_transfer_rate());
				this->io.rd.buffer = std::move(other.io.rd.buffer);
				this->io.wr = std::move(other.io.wr);
				this->sSocket = other.sSocket;
				this->socket_state = other.socket_state;
				this->bDisconnectOnWritesCompleted = other.bDisconnectOnWritesCompleted;
				this->encryption = std::move(other.encryption);
				this->connection = other.connection;
				this->keepalive.latency = other.keepalive.latency;
				this->keepalive.fired_hearbeat_packet = this->keepalive.sent_heartbeat_packet = false;
				this->keepalive.timeout = other.keepalive.timeout;

				//if (&other.handler != &svc) //just an idea, idk if i'll implement
					//this->deadline = other.deadline;
				other.sSocket = INVALID_SOCKET;
				other.socket_state = socket_states::disconnected;
				this->setup_heartbeat_callbacks();
			}

			void socket::setup_heartbeat_callbacks()
			{
				this->on("ping_req", [this](const std::vector<BYTE>&) {
					this->write("pong_resp");
				});
				this->on("pong_resp", [this](const std::vector<BYTE>&) {
					std::lock_guard<std::mutex> lock(keepalive.m_keepalive);
					auto now = std::chrono::steady_clock::now();
					keepalive.latency = now - keepalive.ping;
					keepalive.ping = keepalive.response = now;
					this->keepalive.sent_heartbeat_packet = false;
					keepalive.fired_hearbeat_packet = false;
				});

				//we also setup handled_disconnect cb here too:

				this->on("handled_disconnect", [this](const std::vector<BYTE>&) {
					this->disconnect_on_writes_completed();
				});

			}

			void socket::on_read_msg()
			{
#ifdef _DEBUG
				cout << "Finished reading msg." << endl;
#endif
				std::lock_guard<std::mutex> lock(keepalive.m_keepalive);
				keepalive.last_msg_read = std::chrono::steady_clock::now();
			}

			void socket::on_wrote_msg()
			{
#ifdef _DEBUG
				cout << "Finished writing msg." << endl;
#endif
				std::lock_guard<std::mutex> lock(keepalive.m_keepalive);
				keepalive.last_msg_write = std::chrono::steady_clock::now();
			}

			void socket::set_deadline(const std::chrono::steady_clock::time_point& when)
			{
				std::lock_guard<std::mutex> lock(m_deadline);
				deadline = when;
			}

			void socket::set_deadline(const std::chrono::steady_clock::duration& when)
			{
				std::lock_guard<std::mutex> lock(m_deadline);
				deadline = std::chrono::steady_clock::now() + when;
			}

			std::chrono::steady_clock::time_point socket::get_deadline()
			{
				std::lock_guard<std::mutex> lock(m_deadline);
				return deadline;
			}

			void socket::set_timeout(const std::chrono::seconds timeout)
			{
				std::lock_guard<std::mutex> lock(keepalive.m_keepalive);
				keepalive.timeout = timeout;
			}

			void socket::disable_io(block_io block)
			{
				InterlockedExchange(reinterpret_cast<LONG*>(&this->io.io_block), this->io.io_block | block);
			}

			void socket::enable_io(block_io unblock)
			{
				InterlockedExchange(reinterpret_cast<LONG*>(&this->io.io_block), this->io.io_block & ~unblock);
			}

			void socket::throttle_bandwidth(io_cap io_type, ULONGLONG limit_in_bps)
			{
				if (io_type == io_cap::cap_io_both) {
					for (int i = 0; i < 2; i++)
						bandwidth_cap[i]->throttle(limit_in_bps);
				}
				else
					bandwidth_cap[io_type]->throttle(limit_in_bps);
			}

			ULONGLONG socket::current_transfer_rate_bps(io_cap io_type)
			{
				if (io_type == io_cap::cap_io_both) {
					ULONGLONG result = 0;
					for (int i = 0; i < 2; i++)
						result += bandwidth_cap[i]->current_transfer_rate();
					return result;
				}
				else
					return bandwidth_cap[io_type]->current_transfer_rate();
			}

			void socket::init_bandwidth_cap()
			{
				for (int i = 0; i < 2; i++)
					bandwidth_cap[i] = std::make_unique<cBandwidthThrottler>(1000, 10);
			}

			socket::~socket()
			{
				for (auto& w : io.wr) {
					if (w.write_finish_cb)
						w.write_finish_cb(false);
				}
				if (sSocket != INVALID_SOCKET) {
					::shutdown(sSocket, SD_BOTH);
					::closesocket(sSocket);
				}
			}

			void socket::disconnect_on_writes_completed()
			{
				std::unique_lock<std::recursive_mutex> lock(io.m);
				bDisconnectOnWritesCompleted = true;
				if (io.wr.size() == 0) {
					lock.unlock();
					this->disconnect();
				}
			}

			void socket::on(const std::string & name, std::function<void(const std::vector<BYTE>&)> callback)
			{
				std::lock_guard<std::recursive_mutex> lock(m_callbacks);
				//need to have a bInitializing flag so we don't accidentally hit our own
				//std::list<std::string> reserved_names = { "ping_req", "pong_resp" }; //, "disconnected" //disconnected is not reserved as we must use "on" to register the disconnection notification routine.
				//if (std::find(reserved_names.begin(), reserved_names.end(), name) != reserved_names.end())
					//throw std::runtime_error(name + " is a reserved name!");
				if (callbacks.find(name) != callbacks.end())
					throw std::runtime_error(name + " already exists as a callback!");
				callbacks[name] = callback; //std::make_shared<decltype(callback)>(callback);
			};

			void socket::off(const std::string & name)
			{
				std::lock_guard<std::recursive_mutex> lock(m_callbacks);
				callbacks.erase(name);
			}

			bool socket::hit_deadline()
			{
				std::lock_guard<std::mutex> lock(m_deadline);
				return (deadline != std::chrono::steady_clock::time_point()) && (std::chrono::steady_clock::now() > deadline);
			}

			bool socket::keep_alive()
			{
				std::lock_guard<std::mutex> lock(keepalive.m_keepalive);
				auto now = std::chrono::steady_clock::now();

				if (now - keepalive.ping > keepalive.timeout / 2 && !keepalive.fired_hearbeat_packet) {
					//a ping probe hasn't been sent in 30s+ & the hb packet hasn't been sent.
					keepalive.ping = now;
					keepalive.fired_hearbeat_packet = true;
					this->write("ping_req", std::vector<BYTE>(), [this](bool bWritten) {
						if (bWritten) {
							std::lock_guard<std::mutex> lock(keepalive.m_keepalive);
							this->keepalive.sent_heartbeat_packet = true;
							this->keepalive.ping = std::chrono::steady_clock::now();
						}
						else
							this->keepalive.sent_heartbeat_packet = true;
					});
				}

				//check: NOT (ping has been half of timeout && keepalive.response > timeout) && (last msg read > timeout && heartbeat_packet_entirely_written)
				//slightly modified for the last part: keepalive.last_msg_read now is for last data transmission received(variable name not changed).

				return !((now - keepalive.ping > keepalive.timeout / 2 && now - keepalive.response > keepalive.timeout) && 
					(now - keepalive.last_msg_read > keepalive.timeout && this->keepalive.sent_heartbeat_packet));
			}

			void socket::read_callback(const std::string & name, const std::vector<BYTE>& buffer)
			{
				//std::shared_ptr<callback> cb;
				{
					std::lock_guard<std::recursive_mutex> lock(m_callbacks);
					if (socket_state == socket_states::disconnecting && name == "disconnected")
						InterlockedCompareExchange(reinterpret_cast<LONG*>(&socket_state), socket_states::disconnected, socket_states::disconnecting);

#ifdef DEBUGGING
					cout << "read_callback: " << name << endl;
#endif
					//cout << "callback called: " << name << endl;
					auto it = callbacks.find(name);
					//we can't just do callbacks[name](buffer) because if the callback doesn't exist, it'll create an entry in the map when returned.
					/*if (it != callbacks.end())
						cb = it->second;
					*/
					if (it != callbacks.end())
						it->second(buffer);
					else{
#ifdef DEBUGGING
						cout << "Read CB not found: " << name << endl;
#else
						//throw std::exception("callback not found");
						//MessageBoxA(0, "callback not found!", "", 0);
#endif
					}

				}
			}

			size_t socket::create_queue_ticket()
			{
				auto r = queue_tickets + 1;
				while (InterlockedCompareExchange(&queue_tickets, r, r - 1) != r - 1)
					r = queue_tickets + 1;
				return r;
			}

			bool socket::is_whitelisted_callback(const std::string & callback_name)
			{
				std::list<std::string> whitelist = { "ping_req", "pong_resp", "disconnected" };
				return std::find(whitelist.begin(), whitelist.end(), callback_name) != whitelist.end();
			}

			std::vector<BYTE> socket::serialize_buffer(const std::string& name, const std::vector<BYTE>& buffer)
			{
				std::vector<BYTE> tmp(sizeof(sSerializedNetworkBufferHdr));
				if (encryption.available() && !is_whitelisted_callback(name)) {
					auto enc = encryption.encrypt(buffer);
					auto name_enc = encryption.encrypt(std::vector<BYTE>(name.begin(), name.end()));
					sSerializedNetworkBufferHdr* hdr = (sSerializedNetworkBufferHdr*)&tmp[0];
					hdr->bEncryptionEnabled = true;
					hdr->buffer_size = enc.size();
					hdr->name_size = name_enc.size();
					tmp.reserve(sizeof(sSerializedNetworkBufferHdr) + name_enc.size() + enc.size());
					tmp.insert(tmp.end(), name_enc.begin(), name_enc.end());
					tmp.insert(tmp.end(), std::begin(enc), std::end(enc));
				}
				else {
					sSerializedNetworkBufferHdr* hdr = (sSerializedNetworkBufferHdr*)&tmp[0];
					hdr->bEncryptionEnabled = false;
					hdr->buffer_size = buffer.size();
					hdr->name_size = name.size();
					tmp.reserve(sizeof(sSerializedNetworkBufferHdr) + name.size() + buffer.size());
					tmp.insert(tmp.end(), name.begin(), name.end());
					tmp.insert(tmp.end(), std::begin(buffer), std::end(buffer));
				}
				if (tmp.size() > handler.max_buffer_size())
					throw std::exception("(serialize) size > handler.max_buffer_size()");
				return std::move(tmp);
			}

			std::pair<std::string, std::vector<BYTE>> socket::unserialize_buffer(const std::vector<BYTE>& buffer)
			{
				if (buffer.size() == 0)
					return std::pair<std::string, std::vector<BYTE>>(); //throw std::exception("Cannot unserialize an empty buffer");
				std::lock_guard<std::recursive_mutex> lock(io.m);
				if (buffer.size() < sizeof(sSerializedNetworkBufferHdr))
					throw std::exception("Invalid serialized buffer");
				auto hdr = reinterpret_cast<const sSerializedNetworkBufferHdr*>(buffer.data());

				if (hdr->buffer_size > handler.max_buffer_size())
					throw std::exception("(unserialize) size > handler.max_buffer_size()");
				if (hdr->name_size > handler.max_buffer_size() || hdr->name_size + hdr->buffer_size > handler.max_buffer_size()) //double check
					throw std::exception("(unserialize) size > handler.max_buffer_size()");
				if (buffer.size() < sizeof(sSerializedNetworkBufferHdr) + hdr->name_size + hdr->buffer_size)
					throw std::exception("Invalid serialized buffer");

				std::string name;
				if (hdr->bEncryptionEnabled) {
					if (!encryption.available())
						throw std::exception("encryption is not available but buffer is encrypted.");
					std::vector<BYTE> vec_name_data;
					vec_name_data.insert(vec_name_data.end(), buffer.begin() + sizeof(sSerializedNetworkBufferHdr),
						buffer.begin() + sizeof(sSerializedNetworkBufferHdr) + hdr->name_size);
					auto dec = encryption.decrypt(vec_name_data);
					name.insert(name.end(), dec.begin(), dec.end());
				}
				else {
					name.resize(hdr->name_size);
					memcpy(&name[0], &buffer[sizeof(sSerializedNetworkBufferHdr)], hdr->name_size);
					if (!is_whitelisted_callback(name)) {
						if (encryption.available())
							throw std::exception("Encryption enabled, but buffer was not encrypted!");
					}
				}
				std::vector<BYTE> tmp;
				tmp.reserve(hdr->buffer_size);
				tmp.insert(tmp.begin(), buffer.begin() + sizeof(sSerializedNetworkBufferHdr) + hdr->name_size, buffer.end());

				if (encryption.available())
					return std::pair<std::string, std::vector<BYTE>> { name, is_whitelisted_callback(name) ? tmp : encryption.decrypt(tmp) };
				else
					return std::pair<std::string, std::vector<BYTE>>(name, tmp);
			}

			void socket::write(const std::string& name, const std::vector<BYTE>& buffer, std::function<void(bool)> write_finish_cb)
			{
#ifdef DEBUGGING
				cout << "writing msg: " << name << endl;
#endif
				std::lock_guard<std::recursive_mutex> lock(io.m);
				io.wr.push_back({ 0, serialize_buffer(name, buffer), write_finish_cb });
			}

			void socket::broadcast(const std::string & name, const std::vector<BYTE>& buffer)
			{
				handler.broadcast(name, buffer, shared_from_this());
			}

			void socket::disconnect()
			{
				if (InterlockedCompareExchange(reinterpret_cast<LONG*>(&socket_state), socket_states::disconnecting, socket_states::connected) != socket_states::connected)
					return;

				//this->set_deadline(30s);

				//if we call our disconnection routine directly, it can result in a deadlock if the following conditions match:
				//we're in io_service::shutdown(), calling disconnect_on_writes_completed on a socket(== sockets mutex locked).
				//we're already in socket::read_callback and are trying to call io_service::broadcast
				//better explanation: http://jakascorner.com/blog/2016/01/deadlock.html

				//so to fix this we insert the message into the socket's handler message queue.
				//however this means that the disconnection routine is not guaranteed to fire the disconnection callback.

				{
					std::lock_guard<std::recursive_mutex> io_lock(io.m);
					std::lock_guard<std::mutex> lock(handler.completed_io.m_queue_lock);
					handler.completed_io.rd.push(std::make_pair<std::weak_ptr<socket>, std::vector<BYTE>>(shared_from_this(), this->serialize_buffer("disconnected", std::vector<BYTE>())));
					handler.completed_io.cv.notify_one();
				}
			}

			connector::connector(std::function<void(SOCKET)> default_func)
			{
				this->default_func = default_func;
				bStop = false;
				t = std::thread(&connector::run, this);
			}

			connector::~connector()
			{
				this->cancel();
			}

			void sockets::tcp::async::connector::wait()
			{
				while (size())
					std::this_thread::sleep_for(1ms);
			}

			void connector::cancel()
			{
				bStop = true;
				if (t.joinable())
					t.join();
				for (auto& sock : s)
					::closesocket(sock.first.first);
				s.clear();
			}

			void connector::run()
			{
				while (!bStop) {
					this->check();
					Sleep(50);
				}
			}

			bool connector::connect(const std::string& host, WORD port, const std::chrono::milliseconds& duration)
			{
				return this->connect(host, port, duration, nullptr);
			}

			bool sockets::tcp::async::connector::connect(const std::string & host, WORD port, const std::chrono::milliseconds& expiration, std::function<void(SOCKET)> cb)
			{
				char sPort[6];
				sprintf_s(sPort, "%d", port);
				ADDRINFO hints = {}, *AI;
				hints.ai_family = AF_UNSPEC;
				hints.ai_socktype = SOCK_STREAM;
				hints.ai_protocol = IPPROTO_TCP;
				if (getaddrinfo(host.c_str(), sPort, &hints, &AI) != 0) {
					if (cb)
						cb(INVALID_SOCKET);
					else
						if (default_func)
							default_func(INVALID_SOCKET);
					return false;
				}
				SOCKET sSocket = ::socket(AI->ai_addr->sa_family, SOCK_STREAM, IPPROTO_TCP);
				u_long mode = 1;  //enable non-blocking mode on the socket
				ioctlsocket(sSocket, FIONBIO, &mode);
				bool bSuccess = false;
				if (::connect(sSocket, AI->ai_addr, static_cast<int>(AI->ai_addrlen)) == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) {
					std::lock_guard<std::mutex> lock(m);
					s.push_back(std::make_pair(std::make_pair(sSocket, cb), std::chrono::steady_clock::now() + expiration)); //std::pair<std::pair<SOCKET, std::function<void(SOCKET)>>, std::chrono::steady_clock::time_point>
					bSuccess = true;
				}
				else {
					::closesocket(sSocket);
					if (cb)
						cb(INVALID_SOCKET);
					else
						if (default_func)
							default_func(INVALID_SOCKET);
				}
				freeaddrinfo(AI);
				return bSuccess;
			}

			size_t connector::size() const
			{
				std::lock_guard<std::mutex> lock(m);
				return s.size();
			}

			bool connector::check(FD_SET& s)
			{
				if (s.fd_count == NULL)
					return false;
				TIMEVAL t;
				t.tv_sec = 0;
				t.tv_usec = 1000;
				return ::select(0, nullptr, &s, nullptr, &t) > 0;
			}

			void connector::process(std::list<SOCKET>& valid, FD_SET& w)
			{
				for (u_int i = 0; i < w.fd_count; i++) {
					auto f = std::find_if(s.begin(), s.end(), [&](const std::pair<std::pair<SOCKET, std::function<void(SOCKET)>>, std::chrono::steady_clock::time_point>& value) { //const auto& value
						return value.first.first == w.fd_array[i];
					});
					if (f == s.end()) { //this should never happen
						::closesocket(w.fd_array[i]);
						continue;
					}
					
					u_long mode = 0;
					ioctlsocket(w.fd_array[i], FIONBIO, &mode); //disable non-blocking mode

					if (f->first.second)
						f->first.second(w.fd_array[i]);
					else {
						if (default_func)
							default_func(w.fd_array[i]);
						else
							::closesocket(w.fd_array[i]);
					}

					valid.push_back(w.fd_array[i]);
				}
				FD_ZERO(&w);
			}

			void connector::check()
			{
				std::lock_guard<std::mutex> lock(m);
				for (auto it = s.begin(); it != s.end();) {
					if (std::chrono::steady_clock::now() > it->second) {
						::closesocket(it->first.first);
						if (it->first.second)
							it->first.second(INVALID_SOCKET);
						else
							if (default_func)
								default_func(INVALID_SOCKET);
						it = s.erase(it);
					}
					else
						++it;
				}
				FD_SET w;
				FD_ZERO(&w);
				std::list<SOCKET> valid;
				for (auto& sock : s) {
					FD_SET(sock.first.first, &w);
					if (w.fd_count == FD_SETSIZE)
						if (check(w))
							process(valid, w);
				}

				if (check(w))
					process(valid, w);

				s.remove_if([&](const auto& p) -> bool {
					return std::find(valid.begin(), valid.end(), p.first.first) != valid.end();
				});

			}


			io_service::io_service()
			{
				for (int i = 0; i < 2; i++)
					bandwidth_cap[i] = std::make_unique<cBandwidthThrottler>(1000, 10);

				_max_buffer_size = ASYNC_BUFFER_DEFAULT_MAX_SIZE;
				ullVirtuallyEnforcedSleep_rd = ullVirtuallyEnforcedSleep_wr = 0;
				bStop = false;
				handler = std::thread(&io_service::run, this);
				for (int i = 0; i < 10; i++)
					workers.push_back(std::async(std::launch::async, [this, i]() -> void {
					bool bFlagCanQuit = false;
					while (!stop())
						this->process_work_queue();
				}));
			}

			io_service::~io_service()
			{
				this->shutdown();
			}

			void io_service::quit()
			{
				bStop = true;
			}

			void io_service::shutdown()
			{
				this->bShuttingDown = true;
				this->quit();
				if (handler.joinable())
					handler.join();
				this->completed_io.cv.notify_all();
				for (auto& worker : workers)
					worker.wait();
			}

			void io_service::clean_shutdown()
			{
				this->bShuttingDown = true;
				{
					std::lock_guard<std::recursive_mutex> lock(m_sockets);
					for (auto& socket : sockets) {
						socket->disconnect_on_writes_completed();
						socket->set_deadline(30s);
					}
				}

				while (size())
					std::this_thread::sleep_for(10ms);

				this->shutdown();
			}

			void io_service::broadcast(const std::string & name, const std::vector<BYTE>& buffer, const std::shared_ptr<socket>& exclude, std::function<void(bool)> write_finish_cb)
			{
				std::lock_guard<std::recursive_mutex> lock(m_sockets);
				for (auto& socket : sockets)
					if (socket != exclude)
						socket->write(name, buffer, write_finish_cb);
			}

			void io_service::broadcast(const std::string & name, const std::vector<BYTE>& buffer, const std::list<std::shared_ptr<socket>>& excluded, std::function<void(bool)> write_finish_cb)
			{
				std::lock_guard<std::recursive_mutex> lock(m_sockets);
				for (auto& socket : sockets)
					if (std::find(excluded.begin(), excluded.end(), socket) == excluded.end())
						socket->write(name, buffer, write_finish_cb);
			}

			void io_service::push(const std::shared_ptr<socket>& ptr)
			{
				if (bShuttingDown)
					return;
				std::lock_guard<std::recursive_mutex> lock(m_sockets);
				if (bShuttingDown)
					return;
				sockets.push_back(ptr);
			}

			std::list<std::shared_ptr<socket>>::iterator io_service::begin()
			{
				return sockets.begin();
			}

			std::list<std::shared_ptr<socket>>::iterator io_service::end()
			{
				return sockets.end();
			}

			std::list<std::shared_ptr<socket>>::const_iterator io_service::cbegin() const
			{
				return sockets.cbegin();
			}

			std::list<std::shared_ptr<socket>>::const_iterator io_service::cend() const
			{
				return sockets.cend();
			}

			std::list<std::shared_ptr<socket>>::reverse_iterator io_service::rbegin()
			{
				return sockets.rbegin();
			}

			std::list<std::shared_ptr<socket>>::reverse_iterator io_service::rend()
			{
				return sockets.rend();
			}

			std::list<std::shared_ptr<socket>>::const_reverse_iterator io_service::crbegin() const
			{
				return sockets.crbegin();
			}

			std::list<std::shared_ptr<socket>>::const_reverse_iterator io_service::crend() const
			{
				return sockets.crend();
			}

			size_t io_service::size() const
			{
				std::lock_guard<std::recursive_mutex> lock(m_sockets);
				return sockets.size();
			}

			void io_service::throttle_bandwidth(io_cap io_type, ULONGLONG limit_in_bps)
			{
				if (io_type == io_cap::cap_io_both) {
					for (int i = 0; i < 2; i++)
					bandwidth_cap[i]->throttle(limit_in_bps);
				}
				else
					bandwidth_cap[io_type]->throttle(limit_in_bps);
			}

			ULONGLONG io_service::current_transfer_rate_bps(io_cap io_type)
			{
				if (io_type == io_cap::cap_io_both) {
					ULONGLONG result = 0;
					for (int i = 0; i < 2; i++)
						result += bandwidth_cap[i]->current_transfer_rate();
					return result;
				}
				else
					return bandwidth_cap[io_type]->current_transfer_rate();
			}

			void io_service::run()
			{
				while (!stop()) {
					this->check_sockets();
					/*
					if (size())
						std::this_thread::sleep_for(1ms); //Sleep(1);
					else
						std::this_thread::sleep_for(50ms);
					*/
				}
			}

			void io_service::check_sockets()
			{
				if (bCached_flag_NoSockets)
					std::this_thread::sleep_for(50ms);

				std::unique_lock<std::recursive_mutex> lock(m_sockets);
				//erase disconnected sockets
				bCached_flag_NoSockets = sockets.size() == NULL;

				for (auto it = sockets.begin(); it != sockets.end();) {
					if ((*it)->hit_deadline() || !(*it)->keep_alive() || (*it)->disconnected()) {
						(*it)->disconnect();
#ifdef DEBUGGING
						//for debugging
						if (!(*it)->keep_alive())
							cout << "keepalive fail~" << endl;
						if ((*it)->disconnected())
							cout << "disconnected~" << endl;
						if ((*it)->hit_deadline())
							cout << "hit deadline~" << endl;
#endif
						//if (!has_pending_read_callbacks(*it))
						if ((*it)->disconnected()) //give it time to fire the disconnect callback routine
							it = sockets.erase(it);
						else
							++it;
					}
					else
						it++;
				}
				ULONGLONG cTick = GetTickCount64();

				slist io_list;
				for (auto& socket : sockets) {
					int t = io_none;
					bool can_write = false, can_read = false;
					if (this->ullVirtuallyEnforcedSleep_wr <= cTick && socket->ullVirtuallyEnforcedSleep_wr <= cTick)
						if (socket->io.wr.size())
							t |= io_types::io_write;

					if (this->ullVirtuallyEnforcedSleep_rd <= cTick && socket->ullVirtuallyEnforcedSleep_rd <= cTick)
						t |= io_types::io_read;

					if (t != io_none)
						io_list[socket->sSocket] = std::make_pair(socket, static_cast<io_types>(t));

					socket->bandwidth_cap[cap_io_rd]->write_sample(NULL);
					socket->bandwidth_cap[cap_io_wr]->write_sample(NULL);
				}
				lock.unlock();
				this->check_io(io_list);

				for (int i = 0; i < 2; i++)
					this->bandwidth_cap[i]->write_sample(NULL);
			}

			/*bool io_service::internal_check_io(FD_SET& r, FD_SET& w)
			{
				if (r.fd_count == NULL && w.fd_count == NULL)
					return false;
				TIMEVAL t = { 0 , 10 * 1000 }; //[seconds] , [usec (10ms in usec = 10 * 1000)]
				return ::select(0, r.fd_count ? &r : nullptr, w.fd_count ? &w : nullptr, nullptr, &t) > 0;
			}*/

			void io_service::process_io(std::shared_ptr<socket>& socket, io_types type)
			{
				std::lock_guard<std::recursive_mutex> lock(socket->io.m);
				//if the socket was previously read from, it might've been disconnected.
				//or if the socket was moved to a new handler, then we are no longer allowed to handle it's I/O.
				if (!socket->connected())
					return;

				ULONGLONG cTick = GetTickCount64();

				switch (type) {
				case io_read:
				{
					if (socket->io.io_block & _io_rd)
						return; //read i/o blocked
					if (socket->ullVirtuallyEnforcedSleep_rd > cTick || this->ullVirtuallyEnforcedSleep_rd > cTick)
						return; //read is currently throttled

					char buf[8192];
					
					if (socket->io.rd.buffer.size() < sizeof(sSerializedNetworkBufferHdr)) {
						int i = ::recv(socket->sSocket, buf, static_cast<int>(sizeof(sSerializedNetworkBufferHdr) - socket->io.rd.buffer.size()), 0);
						if (i <= 0) {
#ifdef DEBUGGING
							int wsa_last_error = WSAGetLastError();

							wchar_t *s = NULL;
							FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
								NULL, wsa_last_error,
								MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
								(LPWSTR)&s, 0, NULL);
							wcout << L"WSAGetLastError: " << s << endl;
							LocalFree(s);
							cout << "process_io() -> io_read -> i <= 0" << endl;
#endif
							socket->disconnect();
							return;
						}
						socket->io.rd.buffer.insert(socket->io.rd.buffer.end(), buf, buf + i);
						
						socket->bandwidth_cap[cap_io_rd]->write_sample(i);
						this->bandwidth_cap[cap_io_rd]->write_sample(i);

						if (socket->io.rd.buffer.size() == sizeof(sSerializedNetworkBufferHdr)) { //check if header has been fully received, if so, validate it.
							const sSerializedNetworkBufferHdr* hdr = reinterpret_cast<const sSerializedNetworkBufferHdr*>(socket->io.rd.buffer.data());

							if (hdr->buffer_size > max_buffer_size()) {
#ifdef DEBUGGING
								cout << "process_io() -> io_read -> size > max_buffer_size()" << endl;
#endif
								socket->disconnect();
								return;
							}
							if (hdr->name_size > max_buffer_size() || hdr->buffer_size + hdr->name_size > max_buffer_size()) {
#ifdef DEBUGGING
								cout << "process_io() -> io_read -> name_size > max_buffer_size() || size + name_size > max_buffer_size()" << endl;
#endif
								socket->disconnect();
								return;
							}
						}
					}
					else {
						auto hdr = reinterpret_cast<const sSerializedNetworkBufferHdr*>(socket->io.rd.buffer.data());
						auto full_buffer_size = sizeof(sSerializedNetworkBufferHdr) + hdr->name_size + hdr->buffer_size;
						auto ard = socket->io.rd.buffer.size();
						auto left = static_cast<ULONGLONG>(full_buffer_size - ard);
						auto rd = left > sizeof(buf) ? sizeof(buf) : left;
						auto allowed_limit_socket = socket->bandwidth_cap[cap_io_rd]->get_max_allowed_transfer();
						auto allowed_limit_self = this->bandwidth_cap[cap_io_rd]->get_max_allowed_transfer();

						if (rd > allowed_limit_socket)
							rd = allowed_limit_socket;
						if (rd > allowed_limit_self)
							rd = allowed_limit_self;
						if (rd == 0) {
#ifdef _DEBUG
							cout << "Unable to read" << endl;
#endif
							return;
						}

						int i = ::recv(socket->sSocket, buf, static_cast<int>(rd), 0);
						if (i <= 0) {
#ifdef DEBUGGING
							cout << "process_io() -> io_read -> i <= 0 (2)" << endl;
#endif
							socket->disconnect();
							return;
						}

						socket->bandwidth_cap[cap_io_rd]->write_sample(i);
						
						if (auto enforce_virtual = socket->bandwidth_cap[cap_io_rd]->enforce_virtual()) {
#ifdef _DEBUG
							cout << "Throtting socket bandwidth(rd), for " << enforce_virtual << "ms" << endl;
#endif
							socket->ullVirtuallyEnforcedSleep_rd = cTick + enforce_virtual;
						}
						

						this->bandwidth_cap[cap_io_rd]->write_sample(i);
						if (auto enforce_virtual = bandwidth_cap[cap_io_rd]->enforce_virtual()) {
#ifdef _DEBUG
							cout << "Throtting global bandwidth, for " << enforce_virtual << "ms" << endl;
#endif
							this->ullVirtuallyEnforcedSleep_rd = cTick + enforce_virtual;
						}

						socket->io.rd.buffer.insert(socket->io.rd.buffer.end(), buf, buf + i);
						if (socket->io.rd.buffer.size() == full_buffer_size) {
							socket->on_read_msg();
							//std::lock_guard<std::mutex> completed_io_lock(this->m_queue_lock);
							//this->completed_io_rd.insert(this->completed_io_rd.end(), std::pair<std::weak_ptr<async::socket>, std::vector<BYTE>>(std::weak_ptr<async::socket>(socket), std::move(socket->io.rd.buffer)));
							{
								std::lock_guard<std::mutex> completed_io_lock(this->completed_io.m_queue_lock);
								this->completed_io.rd.push(std::pair<std::weak_ptr<async::socket>, std::vector<BYTE>>(std::weak_ptr<async::socket>(socket), std::move(socket->io.rd.buffer)));
							}
							this->completed_io.cv.notify_one();
						}
					}

					//previously keepalive was message based(it would only be updated when a message was fully received)
					//but this time i'll make it based on data transmission since we have to factor in many issues and concerns(such as the bandwidth limiter causing the message to not be written in time(especially for very LARGE messages)).
					{
						std::lock_guard<std::mutex> lock(socket->keepalive.m_keepalive);
						socket->keepalive.response = std::chrono::steady_clock::now();
					}

				}
				break;
				case io_write:
				{
					if (socket->io.io_block & _io_wr)
						return; //write i/o blocked
					if (socket->ullVirtuallyEnforcedSleep_wr > cTick)
						return; //write is currently throttled


					auto w = socket->io.wr.begin();
					if (w != socket->io.wr.end()) {
#define DEFAULT_MAX_SEND_BUFFER_SIZE 8192 //1024 * 8
						size_t size = w->buffer.size() - w->pos;
						if (size > DEFAULT_MAX_SEND_BUFFER_SIZE)
							size = DEFAULT_MAX_SEND_BUFFER_SIZE;

						if (size == 0) {
#ifdef DEBUGGING
							cout << "process_io() -> io_write -> size == 0" << endl;
#endif
							//this will occur when the socket was moved when inside of the write_finish_cb callback.
							socket->io.wr.erase(w);
							return;
						}

						auto allowed_limit_socket = socket->bandwidth_cap[cap_io_wr]->get_max_allowed_transfer();
						auto allowed_limit_self = this->bandwidth_cap[cap_io_wr]->get_max_allowed_transfer();

						if (size > allowed_limit_socket)
							size = allowed_limit_socket;
						if (size > allowed_limit_self)
							size = allowed_limit_self;
						if (size == 0) {
#ifdef _DEBUG
							cout << "Unable to write." << endl;
#endif
							return;
						}

						int i = ::send(socket->sSocket, (const char*)&w->buffer[w->pos], static_cast<int>(size), 0);
						if (i <= 0) {
#ifdef DEBUGGING
							cout << "process_io() -> io_write -> i <= 0" << endl;
#endif
							if (w->write_finish_cb)
								w->write_finish_cb(false);
							socket->disconnect();
							socket->io.wr.erase(w);
							return;
						}
						w->pos += i;

						socket->bandwidth_cap[cap_io_wr]->write_sample(i);
						if (auto enforce_virtual = socket->bandwidth_cap[cap_io_wr]->enforce_virtual()) {
#ifdef _DEBUG
							cout << "Throtting socket bandwidth, for " << enforce_virtual << "ms" << endl;
#endif
							socket->ullVirtuallyEnforcedSleep_wr = cTick + enforce_virtual;
						}

						this->bandwidth_cap[cap_io_wr]->write_sample(i);
						if (auto enforce_virtual = bandwidth_cap[cap_io_wr]->enforce_virtual()) {
#ifdef _DEBUG
							cout << "Throtting global bandwidth, for " << enforce_virtual << "ms" << endl;
#endif
							this->ullVirtuallyEnforcedSleep_wr = cTick + enforce_virtual;
						}


						if (w->pos == w->buffer.size()) {
							if (w->write_finish_cb)
								w->write_finish_cb(true);
							socket->on_wrote_msg();
							if (socket->sSocket != INVALID_SOCKET) //because the write_finish_cb might've moved the socket, which would've invalidated the iterator so we check if the socket is invalid, if it is, we don't touch it.
								socket->io.wr.erase(w);
							if (socket->bDisconnectOnWritesCompleted && socket->io.wr.size() == NULL)
								socket->disconnect();
						}

					}
				}
				break;
				}
			}

			void io_service::check_io(slist& chk_io)
			{
				if (chk_io.size() == 0) {
					std::this_thread::sleep_for(10ms);
					return;
				}
				std::vector<WSAPOLLFD> pool;
				pool.reserve(chk_io.size());
				for (auto& _fd : chk_io) {
					WSAPOLLFD fd;
					fd.fd = _fd.first;
					fd.events = 0;
					if (_fd.second.second & io_types::io_read)
						fd.events |= POLLRDNORM;
					if (_fd.second.second & io_types::io_write)
						fd.events |= POLLWRNORM;
					pool.push_back(fd);
				}

				int ret;
				if (SOCKET_ERROR == (ret = WSAPoll(pool.data(), static_cast<ULONG>(pool.size()), 100))) {
#ifdef _DEBUG
					cout << "WSAPoll failed!" << endl;
#endif
				}
				else if (ret){
					for (auto& fd : pool) {
						if (fd.revents & POLLRDNORM)
							this->process_io(chk_io[fd.fd].first, io_service::io_read);
						if (fd.revents & POLLWRNORM)
							this->process_io(chk_io[fd.fd].first, io_service::io_write);
						if ((fd.revents & POLLERR) || (fd.revents & POLLHUP) || (fd.revents & POLLNVAL)) {
#ifdef _DEBUG
							printf("Detected Invalid Socket!\r\n");
#endif
							chk_io[fd.fd].first->disconnect();
						}
					}
				}

				/*if (rd.size() == NULL && wr.size() == NULL) {
					std::this_thread::sleep_for(10ms);
					return;
				}
				//FD_SETSIZE
				FD_SET r, w;
				FD_ZERO(&r);
				FD_ZERO(&w);
				auto rd_it = rd.begin(), wr_it = wr.begin();
				while (rd_it != rd.end() || wr_it != wr.end()) {
					if (rd_it != rd.end()) {
						FD_SET(rd_it->first, &r);
						++rd_it;
					}
					if (wr_it != wr.end()) {
						FD_SET(wr_it->first, &w);//FD_SET(wr_it++->first, &w);
						++wr_it;
					}

					if (r.fd_count == FD_SETSIZE || w.fd_count == FD_SETSIZE) {
						if (this->internal_check_io(r, w)) { //returns true if select > 0.	
							for (u_int i = 0; i < r.fd_count; i++) {
								this->process_io(rd[r.fd_array[i]], io_service::io_read);
							}

							for (u_int i = 0; i < w.fd_count; i++) 
								this->process_io(wr[w.fd_array[i]], io_service::io_write);
						}
						FD_ZERO(&r);
						FD_ZERO(&w);
					}
				}
				//check whatever is left
				if (this->internal_check_io(r, w)) {
					for (u_int i = 0; i < r.fd_count; i++)
						this->process_io(rd[r.fd_array[i]], io_service::io_read);
					for (u_int i = 0; i < w.fd_count; i++)
						this->process_io(wr[w.fd_array[i]], io_service::io_write);
				}
				*/
			}

			void io_service::process_work_queue()
			{
				//old code:
				/*
				std::unique_lock<std::mutex> io_completed_lock(m_queue_lock);
				auto it = completed_io_rd.begin();
				if (it != completed_io_rd.end()) {
					auto ptr = it->first.lock();
					if (!ptr || ptr->disconnected()) {
						completed_io_rd.erase(it);
						return;
					}
					std::unique_lock<std::mutex> cb_lock(ptr->read_cb_mutex, std::defer_lock);
					if (!cb_lock.try_lock())
						return;
					auto data = std::move(it->second);
					completed_io_rd.erase(it);
					io_completed_lock.unlock();
					try {
						auto unserialized = ptr->unserialize_buffer(data);
						ptr->read_callback(unserialized.first, unserialized.second);
					}
					catch (std::exception& e) { //ex: unserialize_buffer might throw if encryption fails to decrypt.
						UNREFERENCED_PARAMETER(e);
						ptr->disconnect();
					}
				}
				*/

				std::unique_lock<std::mutex> lock(completed_io.m_queue_lock);
				completed_io.cv.wait(lock, [this]() -> bool { return stop() || !completed_io.rd.empty(); });
				if (completed_io.rd.size()) {
					auto pair = std::move(completed_io.rd.front());
					completed_io.rd.pop();
					auto ptr = pair.first.lock();
					if (!ptr) //|| ptr->disconnected()
						return;
					auto ticket = ptr->create_queue_ticket();
					lock.unlock();
					try {
						while (ticket != ptr->current_queue_ticket)
							Sleep(1);
						auto unserialized = ptr->unserialize_buffer(pair.second);
						ptr->read_callback(unserialized.first, unserialized.second);
					}
					catch (std::exception& e) { //ex: unserialize_buffer might throw if encryption fails to decrypt. Or the read callback may throw an unhandled exception to cause a disconnection.
#ifdef DEBUGGING
						cout << "io_service::process_work_queue() - caught exception: " << (e.what() ? e.what() : "null") << endl;
#endif
						UNREFERENCED_PARAMETER(e);
						ptr->disconnect();
					}
					InterlockedIncrement(&ptr->current_queue_ticket);
				}
			}


			listener::listener()
			{
				bStop = true;
				bDisconnected = true;
				iSockets = NULL;
				wPort = NULL;
				func = nullptr;
			}

			listener::~listener()
			{
				this->close();
			}

			void listener::close(bool from_inside_lthread)
			{
				bDisconnected = bStop = true;
				if (!from_inside_lthread) {
					if (t.joinable())
						t.join();
				}
				for (int i = 0; i < iSockets; i++)
					::closesocket(sSockets[i]);
				iSockets = NULL;
				wPort = NULL;
				for (int i = 0; i < 2; i++)
					IPStatus[i] = false;
				func = nullptr;
			}

			bool listener::listen(WORD wPort, listener_flags flags)
			{
				this->close();
				addrinfo *result = nullptr, *ptr = nullptr, hints;
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
				if (getaddrinfo(nullptr, port, &hints, &result) == 0) {
					for (ptr = result; ptr != nullptr; ptr = ptr->ai_next) {
						if (ptr->ai_protocol != IPPROTO_TCP)
							continue;
						if (iSockets >= FD_SETSIZE)
							break;

						sSockets[iSockets] = ::socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
						if (sSockets[iSockets] == INVALID_SOCKET)
							continue;
						if (flags & listener_flags::LOOPBACK) {
							SOCKADDR_STORAGE addr{};
							addr.ss_family = ptr->ai_family;
							switch (ptr->ai_family) {
							case AF_INET:
								InetPton(AF_INET, TEXT("127.0.0.1"), &addr); //INADDR_LOOPBACK
								break;
							case AF_INET6:
								InetPton(AF_INET6, TEXT("::1"), &addr); //&reinterpret_cast<SOCKADDR_IN6*>(ptr->ai_addr)->sin6_addr
								break;
							}
							if (::bind(sSockets[iSockets], (const sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
								::closesocket(sSockets[iSockets]);
								continue;
							}
						}
						else {
							if (::bind(sSockets[iSockets], ptr->ai_addr, static_cast<int>(ptr->ai_addrlen)) == SOCKET_ERROR) {
								::closesocket(sSockets[iSockets]);
								continue;
							}
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
						this->wPort = wPort;
						iSockets++;
						bStop = bDisconnected = false;
					}
					freeaddrinfo(result);
					return !(bDisconnected = iSockets == NULL);
				}
				else
					return false;
			}

			void listener::accept(std::function<void(SOCKET)> f)
			{
				if (bStop || func)
					return;
				func = f;
				t = std::thread(&listener::run, this);
			}

			void listener::run()
			{
				TIMEVAL t;
				t.tv_sec = 0;
				t.tv_usec = 20000;

				while (!bStop && !disconnected())
				{
					FD_SET set;
					FD_ZERO(&set);
					for (int i = 0; i < iSockets; i++)
						FD_SET(sSockets[i], &set);
					int i;
					if ((i = select(0, &set, nullptr, nullptr, &t)) > 0) {
						SOCKADDR_STORAGE discard;
						int size = sizeof(discard);
						SOCKET s = ::accept(set.fd_array[0], reinterpret_cast<LPSOCKADDR>(&discard), &size);
						if (s != INVALID_SOCKET) {
							if (func) {
								func(s);
							}
							else
								::closesocket(s);
						}
					}
					else if (i == SOCKET_ERROR) //returns 0 if timed out, -1 means an error occured.
						this->close(true);
					//Sleep(100);
				}
			}
		}
	}
}
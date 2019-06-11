#pragma once
#include <bitflg.hpp>
#include <queue>
#include <condition_variable>
#include <sockets/sampler.h>

namespace sockets {
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

		namespace async {

			struct sNetworkBuffer_Wr { //perhaps rename to sIOWriteRequest, looks more fancy?
				size_t pos;
				std::vector<BYTE> buffer;
				std::function<void(bool)> write_finish_cb;
			};

			enum socket_states:LONG {
				connected,
				disconnecting,
				disconnected
			};

			enum block_io :LONG {
				io_block_none,
				_io_rd = BitFlags::option1,
				_io_wr = BitFlags::option2,
				_io_both = _io_rd | _io_wr
			};

			enum io_cap {
				cap_io_rd,
				cap_io_wr,
				cap_io_both
			};

			//note: socket provides an automatic keepalive system.
			class io_service;
			class socket:public std::enable_shared_from_this<socket> {
			public: //I was actually thinking of making a .attach(io) method, instead of using a reference to io in the constructor. But oh well!
				socket(io_service& io, SOCKET s);
				socket(io_service& io, socket&& other); //allows you to move the socket to a new i/o handler(service). WARNING: it only moves the socket, encryption, bDisconnected(connection status), and io buffers. You will need to reset any callbacks & deadline timer yourself.
				socket(const socket& other) = delete;
				virtual ~socket();
				void write(const std::string& name, const std::vector<BYTE>& buffer = std::vector<BYTE>(), std::function<void(bool)> write_finish_cb = nullptr); //send a message to our peer.
				void broadcast(const std::string& name, const std::vector<BYTE>& buffer = std::vector<BYTE>()); //broadcasts a message to all peers except itself.
				std::string ip() const { return connection._ip; };
				WORD remote_port() const { return connection.remote_port; };
				bool disconnected() const { return socket_state == socket_states::disconnected; };
				bool disconnecting() const { return socket_state == socket_states::disconnecting; };
				bool connected() const { return socket_state == socket_states::connected; };
				void disconnect(); // { bDisconnected = true; /*to-do: implement disconnection notification routine*/ };
				void disconnect_on_writes_completed();
				void on(const std::string& name, std::function<void(const std::vector<BYTE>&)> callback);
				void off(const std::string& name);
				void set_deadline(const std::chrono::steady_clock::time_point& when);
				void set_deadline(const std::chrono::steady_clock::duration& when);
				void set_encryption(const Crypto::AES& aes) {
					std::lock_guard<std::recursive_mutex> lock(io.m);
					this->encryption = aes;
				};
				bool encrypted() const { 
					std::lock_guard<std::recursive_mutex> lock(io.m);
					return encryption.available(); 
				};
				std::chrono::steady_clock::time_point get_deadline();
				std::shared_ptr<socket> share() { return shared_from_this(); };
				void set_timeout(const std::chrono::seconds timeout = std::chrono::seconds(60));

				void disable_io(block_io block);
				void enable_io(block_io enable);

				void throttle_bandwidth(io_cap io_type, ULONGLONG limit_in_bps);
				ULONGLONG current_transfer_rate_bps(io_cap io_type);
			private:
				void init_bandwidth_cap();
				friend class io_service;
				struct sConnectionInfo{
				std::string _ip;
				WORD remote_port;
				}connection;

				struct {
					std::mutex m_keepalive;
					std::chrono::time_point<std::chrono::steady_clock> response, last_msg_read, last_msg_write;
					std::chrono::time_point<std::chrono::steady_clock> ping;
					bool fired_hearbeat_packet, sent_heartbeat_packet;
					std::chrono::nanoseconds latency;
					std::chrono::seconds timeout; //make sure to increase timeout if you increase maximum msg buffer size(handled by io_service), otherwise you risk disconnecting slow peers if they fail to receive an entire message within the timeout time.
				}keepalive; //https://en.wikipedia.org/wiki/Keepalive aka heartbeat.

				std::chrono::steady_clock::time_point deadline;
				std::mutex m_deadline;
				std::recursive_mutex m_callbacks;
				typedef std::function<void(const std::vector<BYTE>&)> callback;
				//std::map<std::string, std::shared_ptr<callback>> callbacks;
				std::map<std::string, callback> callbacks;
				SOCKET sSocket;
				socket_states socket_state;
				bool bDisconnectOnWritesCompleted;
				struct {
					mutable std::recursive_mutex m;
					std::list<sNetworkBuffer_Wr> wr;
					struct {
						std::vector<BYTE> buffer;
					}rd;

					block_io io_block;
				}io;
				size_t queue_tickets = NULL;
				size_t current_queue_ticket = 1;
				size_t create_queue_ticket();

				bool is_whitelisted_callback(const std::string& callback_name);

				std::vector<BYTE> serialize_buffer(const std::string& name, const std::vector<BYTE>& buffer);
				std::pair<std::string, std::vector<BYTE>> unserialize_buffer(const std::vector<BYTE>& buffer);
				void read_callback(const std::string& name, const std::vector<BYTE>& buffer);
				bool hit_deadline();
				bool keep_alive(); //returns false if timed out
				void setup_heartbeat_callbacks();
				void on_read_msg();
				void on_wrote_msg();
			protected:
				ULONGLONG ullVirtuallyEnforcedSleep_rd, ullVirtuallyEnforcedSleep_wr;
				std::unique_ptr<cBandwidthThrottler> bandwidth_cap[2];
				io_service& handler;
				Crypto::AES encryption; //since messages are processed one at a time, we don't need a mutex/have to worry about a race condition.
			};

			//only allows you to define a single callback function per instance.
			class connector {
			public:
				connector(std::function<void(SOCKET)> default_func = nullptr);
				~connector();
				bool connect(const std::string& host, WORD port, const std::chrono::milliseconds& duration = std::chrono::seconds(20));
				bool connect(const std::string& host, WORD port, const std::chrono::milliseconds& duration, std::function<void(SOCKET)> callback);
				size_t size() const; //queue'd socket size(not yet complete)
				void wait();
				void cancel();
			private:
				mutable std::mutex m;
				std::list<std::pair<std::pair<SOCKET, std::function<void(SOCKET)>>, std::chrono::steady_clock::time_point>> s;
				bool bStop;
				void run();
				void check();
				bool check(FD_SET& s);
				void process(std::list<SOCKET>& valid, FD_SET& w);
				std::thread t;
				std::function<void(SOCKET)> default_func;
			};

#ifndef ASYNC_BUFFER_DEFAULT_MAX_SIZE
#define ASYNC_BUFFER_DEFAULT_MAX_SIZE 1024 * 256 //256 KiB
#endif

			//uses the proactor design pattern: https://en.wikipedia.org/wiki/Proactor_pattern
			class io_service {
			public:
				io_service();
				io_service(io_service&&) = delete;
				io_service(const io_service&) = delete;
				void operator=(io_service&&) = delete;
				void operator=(const io_service&) = delete;
				~io_service();
				void quit();
				void shutdown();
				void clean_shutdown();
				void broadcast(const std::string & name, const std::vector<BYTE>& buffer = std::vector<BYTE>(), const std::shared_ptr<socket>& exclude = std::shared_ptr<socket>(), std::function<void(bool)> write_finish_cb = nullptr); //broadcasts a message to all except for the excluded peer.
				void broadcast(const std::string & name, const std::vector<BYTE>& buffer, const std::list<std::shared_ptr<socket>>& excluded/* = std::list<std::shared_ptr<socket>>()*/, std::function<void(bool)> write_finish_cb = nullptr); //same as above, except you can specify multiple excluded peers.
				void push(const std::shared_ptr<socket>& ptr);
				//while the io_service wasn't specifically made to access each socket individually(rather it was made for the purpose of broadcasting a message to an entire group), you can still do so.
				std::unique_lock<std::recursive_mutex> acquire_sockets_lock() const { return std::unique_lock<std::recursive_mutex>(m_sockets); };
				std::recursive_mutex& sockets_mutex() { return m_sockets; };
				std::list<std::shared_ptr<socket>>::iterator begin();
				std::list<std::shared_ptr<socket>>::iterator end();
				std::list<std::shared_ptr<socket>>::const_iterator begin() const { return cbegin(); };
				std::list<std::shared_ptr<socket>>::const_iterator end() const { return cend(); };
				std::list<std::shared_ptr<socket>>::const_iterator cbegin() const;
				std::list<std::shared_ptr<socket>>::const_iterator cend() const;
				std::list<std::shared_ptr<socket>>::reverse_iterator rbegin();
				std::list<std::shared_ptr<socket>>::reverse_iterator rend();
				std::list<std::shared_ptr<socket>>::const_reverse_iterator crbegin() const;
				std::list<std::shared_ptr<socket>>::const_reverse_iterator crend() const;
				size_t size() const; //thread safe
				size_t max_buffer_size() const { return _max_buffer_size; };
				void set_max_buffer_size(size_t new_size) { InterlockedExchange(&_max_buffer_size, new_size); };
				void throttle_bandwidth(io_cap io_type, ULONGLONG limit_in_bps); //throttle bandwidth(global)
				ULONGLONG current_transfer_rate_bps(io_cap io_type);
			private:
				ULONGLONG ullVirtuallyEnforcedSleep_rd, ullVirtuallyEnforcedSleep_wr;
				std::unique_ptr<cBandwidthThrottler> bandwidth_cap[2];
				friend class socket;
				bool bShuttingDown = false, bCached_flag_NoSockets = true;

				enum io_types {
					io_none,
					io_read = BitFlags::option1,
					io_write = BitFlags::option2
				};
				using slist = std::map<SOCKET, std::pair<std::shared_ptr<socket>, io_types>>;
				size_t _max_buffer_size;
				bool bStop;
				bool stop() const { return bStop; };
				void run();
				void check_sockets(); //check if we need to process i/o
				//void check_io(slist& rd, slist& wr);
				void check_io(slist& chk_io);
				//bool internal_check_io(FD_SET& r, FD_SET& w);
				void process_io(std::shared_ptr<socket>& socket, io_types type);
				void process_work_queue(); //processes completed i/o queue
				std::thread handler;
				mutable std::recursive_mutex m_sockets;
				std::list<std::shared_ptr<socket>> sockets;
				std::list<std::future<void>> workers;
				
				struct {
					std::mutex m_queue_lock;
					std::queue < std::pair<std::weak_ptr<socket>, std::vector<BYTE>>> rd;
					std::condition_variable cv;
				}completed_io;
				
				//std::list < std::pair<std::weak_ptr<socket>, std::vector<BYTE>>> completed_io_rd;
			};

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
				~listener();
				bool listen(WORD wPort, listener_flags flags = ANY | IPv4);
				void accept(std::function<void(SOCKET)> f);
				bool status(internet_protocols protocol) const { return IPStatus[protocol]; };
				void close(bool from_inside_lthread = false);
				bool disconnected() const { return bDisconnected; };
				WORD port() const { return this->wPort; };
			private:
				void run();
				std::thread t;
				bool bStop, bDisconnected, IPStatus[2];
				int iSockets;
				WORD wPort;
				SOCKET sSockets[FD_SETSIZE];
				std::function<void(SOCKET)> func;
			};

		};

	};

};
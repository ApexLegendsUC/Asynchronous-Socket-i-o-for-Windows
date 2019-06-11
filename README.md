# Asynchronous-Socket-i-o-for-Windows
Asynchronous Socket i/o for Windows (C++) type B

Just an example showing asynchronous socket i/o delievered through callbacks, with encryption support, deadlines(maximum amount of time socket can remain connected), keepalive system, as well as a bandwidth throttler.

e.g. 
server:
socket->on("hello.world", [](const std::vector<BYTE>& msg){
cout << "(server received msg)" << std::string(msg.begin(), msg.end()) << endl;
socket->write("hello.world.from.server", std::vector<BYTE>(msg.begin(), msg.end());
});

Made back in 2016 or 2017.

different version that's being worked on: https://github.com/ApexLegendsUC/winsock-asychronous-socket-i-o-c--

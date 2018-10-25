// VUT FIT 3BIT
// ISA 2018/2019
// Project: Programovani sitove sluzby
// Variant: 2 - Export DNS informaci pomoci protokolu Syslog
// Author: Vladimir Dusek, xdusek27
// Date: 30/9/2018
// File: syslog.cpp

#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <string>
#include "syslog.h"
#include "utils.h"

using namespace std;

Syslog::Syslog():
    m_server_address(""),
    m_socket_fd(0),
    m_connected(false)
{
}

Syslog::~Syslog()
{
    if (m_connected) {
        disconnect();
    }
}

bool Syslog::connected()
{
    return m_connected;
}

void Syslog::set_server_address(std::string address)
{
    m_server_address = address;
}

void Syslog::connect()
{
    if (m_connected) {
        return;
    }

    addrinfo hints, *res, *res_s;

    memset(&hints, 0, sizeof(addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    if (getaddrinfo(m_server_address.c_str(), to_string(SYSLOG_PORT).c_str(), &hints, &res_s) != 0) {
        throw SyslogException("connection to the syslog server failed\ngetaddrinfo(): " +
            string(strerror(errno)) + "\n");
    }

    for (res = res_s; res != nullptr; res = res->ai_next) {
        if ((m_socket_fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) == -1) {
            continue;
        }

        if (::connect(m_socket_fd, res->ai_addr, res->ai_addrlen) == -1) {
            close(m_socket_fd);
            continue;
        }
        break;
    }

    if (res == nullptr) {
        throw SyslogException("connection to the syslog server failed\nsocket(), connect(): " +
            string(strerror(errno)) + "\n");
    }

    freeaddrinfo(res_s);
    m_connected = true;

    DEBUG_PRINT("Connected to the syslog server!\n\n");
}

void Syslog::send_log(std::string message)
{
    if (!m_connected) {
        throw SyslogException("sending log to the syslog server failed\nnot connected");
    }

    string log = "<" + PRIORITY + ">" + to_string(VERSION) + " " + get_timestamp() + " " +
        get_ip() + " " + PROJ_NAME + " --- " + message;

    DEBUG_PRINT("Sending:\n");
    DEBUG_PRINT(log + "\n\n");

    if (send(m_socket_fd, log.c_str(), log.size(), 0) == -1) {
        throw SyslogException("sending log to the syslog server failed\nsend(): " + string(strerror(errno)) + "\n");
    }
}

void Syslog::disconnect()
{
    if (m_connected) {
        close(m_socket_fd);
        m_connected = false;
    }

    DEBUG_PRINT("Disconnected from the syslog server.\n\n");
}

string Syslog::get_timestamp()
{
    char buffer[BUFFER_SIZE] = {0};
    time_t time_now = time(nullptr);
    tm *ts = gmtime(&time_now); // Current UTC time

    if (strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", ts) == 0) {
        throw SystemException("strftime failed\n");
    }

    // Find out decimal part of seconds
    string time_stamp = string(buffer);
    timeval tval;

    if (gettimeofday(&tval, nullptr) == -1) {
        throw SystemException("gettimeofday failed\ngettimeofday(): " +
                              string(strerror(errno)) + "\n");
    }

    time_stamp.append(".");
    time_stamp.append(to_string(tval.tv_usec).substr(0, 3));
    time_stamp.append("Z");

    return time_stamp;
}

string Syslog::get_ip()
{
    if (!m_client_ip.empty()) {
        return m_client_ip;
    }

    sockaddr_in *addr = nullptr;
    ifaddrs *list_ifaddrs = nullptr;

    if (getifaddrs(&list_ifaddrs) == -1) {
        throw SystemException("cannot get ip address of network interface\ngetifaddrs(): " +
                              string(strerror(errno)) + "\n");
    }

    for (ifaddrs *elem = list_ifaddrs; elem != nullptr; elem = elem->ifa_next) {
        // Don't want loopback
        if ((elem->ifa_flags & IFF_LOOPBACK) == 0 && elem->ifa_addr && elem->ifa_addr->sa_family == AF_INET) {
            addr = reinterpret_cast<sockaddr_in *>(elem->ifa_addr);
            m_client_ip = inet_ntoa(addr->sin_addr);
        }
    }

    freeifaddrs(list_ifaddrs);

    return m_client_ip;
}

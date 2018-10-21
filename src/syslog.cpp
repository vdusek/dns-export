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

#include <iostream>

#include "syslog.h"
#include "utils.h"

using namespace std;

/*

struct sockaddr {
    sa_family_t sa_family;
    char        sa_data[14];
};

struct sockaddr_in {
    short            sin_family;   // e.g. AF_INET
    unsigned short   sin_port;     // e.g. htons(3490)
    struct in_addr   sin_addr;     // see struct in_addr, below
    char             sin_zero[8];  // zero this if you want to
};

struct in_addr {
    unsigned long s_addr;  // load with inet_aton()
};

 */


Syslog::Syslog(std::string address):
    m_addr_server(address),
    m_socket_fd(0),
    m_connected(false)
{
}

Syslog::~Syslog()
{
    cerr << "destructor called" << endl;
    if (m_connected) {
        disconnect();
    }
}

string Syslog::get_timestamp()
{
    const char *months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    time_t t = time(nullptr);
    tm *tm = localtime(&t);
    char timestamp[20];
    snprintf(timestamp, sizeof(timestamp), "%s %2d %.2d:%.2d:%.2d", months[tm->tm_mon],
            tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);
    return timestamp;
}

string Syslog::get_ip()
{
    if (!m_my_ip.empty()) {
        return m_my_ip;
    }

    struct sockaddr_in *addr;
    ifaddrs *addrs, *tmp = nullptr;
    getifaddrs(&addrs);
    tmp = addrs;

    while (tmp)  {
        if ((tmp->ifa_flags & IFF_LOOPBACK) == 0 /* we dont want loopback address */
            && tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET)
        {
            addr = (struct sockaddr_in *)tmp->ifa_addr;
            // found IP address of sender
            m_my_ip = inet_ntoa(addr->sin_addr);
        }

        tmp = tmp->ifa_next;
    }

    freeifaddrs(addrs);
    return m_my_ip;
}

void Syslog::connect()
{
    addrinfo hints, *res, *res_s;

    memset(&hints, 0, sizeof(addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    if (getaddrinfo(m_addr_server.c_str(), to_string(SYSLOG_PORT).c_str(), &hints, &res_s) != 0) {
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

    // memory for res_s was dynamically allocated
    freeaddrinfo(res_s);
    m_connected = true;

    cerr << "Successfully connected to the syslog server!" << endl << endl; // debug
}

void Syslog::send_log(std::string message)
{
    if (!m_connected) {
        throw SyslogException("sending log to the syslog server failed\nnot connected");
    }

    // ToDo: syntax of syslog msg (private methods)

    string log = "<" + PRIORITY + ">" + get_timestamp() + " " + get_ip() + " dns-export --- " + message;

    cerr << "sending \"" << log << "\" to the syslog server" << endl; // debug

    if (send(m_socket_fd, message.c_str(), message.size(), 0) == -1) {
        throw SyslogException("sending log to the syslog server failed\nsend(): " + string(strerror(errno)) + "\n");
    }

    cerr << "Log was sent successfully!" << endl << endl;
}

void Syslog::disconnect()
{
    if (m_connected) {
        close(m_socket_fd);
        m_connected = false;
        cerr << "disconnected from the syslog server" << endl; // debug
    }
    else {
        cerr << "you're already disconnected from the syslog server" << endl; // debug
    }
}

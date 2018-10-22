// VUT FIT 3BIT
// ISA 2018/2019
// Project: Programovani sitove sluzby
// Variant: 2 - Export DNS informaci pomoci protokolu Syslog
// Author: Vladimir Dusek, xdusek27
// Date: 30/9/2018
// File: syslog.h

#pragma once

#include <netinet/in.h>
#include <string>

// Syslog port
const int SYSLOG_PORT = 514;

// Facility: local use 0
const int FACILITY = 16;

// Severity: informational
const int SEVERITY = 6;

// Syslog message priority
const std::string PRIORITY = std::to_string((FACILITY * 8) + SEVERITY);

// Syslog protocol version
const int VERSION = 1;


class Syslog {
private:
    std::string m_server_address;
    std::string m_client_ip;
    int m_socket_fd;
    bool m_connected;

    /**
     * Get timestamp for log.
     */
    std::string get_timestamp();

    /**
     * Get IP for log.
     */
    std::string get_ip();

public:
    /**
     * Constructor, set default members.
     */
    explicit Syslog();

    /**
     * Destructor calls disconnect() if connected.
     */
    ~Syslog();

    /**
     * Set syslog server address.
     */
    void set_server_address(std::string address);

    /**
     * Connect to the syslog server.
     */
     void connect();

    /**
     * Send message to the log server.
     */
    void send_log(std::string message);

    /**
     * Disconnect from the syslog server.
     */
    void disconnect();
};

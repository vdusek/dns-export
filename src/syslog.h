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

// Default syslog port
const int SYSLOG_PORT = 514;

// Local0 Facility
const int LOCAL0_FACILITY = 16;

// Informational Severity
const int INFORMATIONAL_SEVERITY = 6;

// Syslog message priority
const std::string PRIORITY = std::to_string((LOCAL0_FACILITY * 8) + INFORMATIONAL_SEVERITY);


class Syslog {
private:
    std::string m_addr_server;
    std::string m_my_ip;
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
    explicit Syslog(std::string address);

    /**
     * Destructor calls disconnect() if connected.
     */
    ~Syslog();

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


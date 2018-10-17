// VUT FIT 3BIT
// ISA 2018/2019
// Project: Programovani sitove sluzby
// Variant: 2 - Export DNS informaci pomoci protokolu Syslog
// Author: Vladimir Dusek, xdusek27
// Date: 30/9/2018
// File: config.h

#pragma once

#include <string>

/**
 * Parser of command line arguments.
 */
class ArgParser {
private:
    int m_argc;
    char **m_argv;
    std::string m_resource;
    std::string m_interface;
    std::string m_server;
    u_int m_timeout;

public:
    /**
     * Constructor, set all attributes to default values.
     */
    ArgParser(int argc, char **argv);

    /**
     * Default destructor.
     */
    ~ArgParser();

    /**
     * Get resource arg.
     */
    std::string resource();

    /**
     * Get interface arg.
     */
    std::string interface();

    /**
     * Get server arg.
     */
    std::string server();

    /**
     * Get timeout arg.
     */
    u_int timeout();

    /**
     * Parse command line arguments.
     */
    void parse();

    /**
     * Print all attributes on stderr for purpose of debugging.
     */
    void print();
};

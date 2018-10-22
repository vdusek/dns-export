// VUT FIT 3BIT
// ISA 2018/2019
// Project: Programovani sitove sluzby
// Variant: 2 - Export DNS informaci pomoci protokolu Syslog
// Author: Vladimir Dusek, xdusek27
// Date: 30/9/2018
// File: arg_parser.h

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
    ArgParser();

    /**
     * Default destructor.
     */
    ~ArgParser();

    /**
     * Set argc and argv.
     */
    void set_args(int argc, char **argv);

    /**
     * Get resource arg.
     */
    std::string get_resource();

    /**
     * Get interface arg.
     */
    std::string get_interface();

    /**
     * Get server arg.
     */
    std::string get_server();

    /**
     * Get timeout arg.
     */
    u_int get_timeout();

    /**
     * Parse command line arguments.
     */
    void parse();

    /**
     * Print all attributes on stderr for purpose of debugging.
     */
    void debug_print();
};

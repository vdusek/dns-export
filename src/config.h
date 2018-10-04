// VUT FIT 3BIT
// ISA 2018/2019
// Project: Programovani sitove sluzby
// Variant: 2 - Export DNS informaci pomoci protokolu Syslog
// Author: Vladimir Dusek, xdusek27
// Date: 30/9/2018
// File: config.h

#pragma once

#include <iostream>
#include <string>

/**
 * Help text
 */
const std::string HELP_TEXT = "Usage:\n"
    "$ ./dns-export [-r file.pcap] [-i interface] [-s syslog-server] [-t seconds] [-h]\n"
    "    -r, --resource         description ToDo\n"
    "    -i, --interface        description ToDO\n"
    "    -s, --server           description ToDo\n"
    "    -t, --timeout          value of timeout in seconds\n"
    "    -h, --help             print this help";

/**
 * Parsing command line options. Print help on stdout if it is required or
 * call error() if there is a problem.
 */
class Config {
private:
    std::string resource;
    std::string interface;
    std::string server;
    int timeout;
    bool help;

public:
    /**
     * Constructor, set all attributes to default values.
     */
    Config();

    /**
     * Destructor.
     */
    ~Config();

    /**
     * Get resource arg
     */
    std::string get_resource();

    /**
     * Get interface arg
     */
    std::string get_interface();

    /**
     * Get resource arg
     */
    std::string get_server();

    /**
     * Get timeout arg
     */
    int get_timeout();

    /**
     * Get help arg
     */
    bool get_help();

    /**
     * Parse command line arguments.
     */
    void parse_arguments(int argc, char *argv[]);

    /**
     * Print help on stdout.
     */
    void print_help();

    /**
     * Print all attributes on stderr for purpose of debugging.
     */
    void print_arguments();
};

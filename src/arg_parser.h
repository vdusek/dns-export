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
 * Parser of command line arguments.
 */
class ArgParser {
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
    ArgParser();

    /**
     * Destructor.
     */
    ~ArgParser();

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
    void parse(int argc, char **argv);

    /**
     * Print all attributes on stderr for purpose of debugging.
     */
    void print();
};

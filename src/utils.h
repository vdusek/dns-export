// VUT FIT 3BIT
// ISA 2018/2019
// Project: Programovani sitove sluzby
// Variant: 2 - Export DNS informaci pomoci protokolu Syslog
// Author: Vladimir Dusek, xdusek27
// Date: 30/9/2018
// File: error.h

#pragma once

#include <stdexcept>
#include <string>

/**
 * All types of return codes.
 */
enum RetCode {
    RET_INV_ARGS = 1,    // invalid command line options
    RET_INV_PCAP = 2,    // invalid pcap file
    RET_SYS = 99         // system error (malloc, socket, etc.)
};

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
 * Print help on stdout.
 */
void print_help();

/**
 * Print error message on stderr and exit the program according
 * to the ret_code parameter.
 */
void error(RetCode ret_code, std::string message);

void signal_handler(int sig);

/**
 * Exception for arguments failures.
 */
class ArgumentException: public std::invalid_argument {
public:
    ArgumentException(std::string const &message): std::invalid_argument(message) {}
};

/**
 * Exception for invalid pcap file.
 */
//class PcapException



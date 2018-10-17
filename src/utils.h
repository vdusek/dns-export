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
#include <unordered_map>

const int DIGEST_PRINT_LEN = 20;
const int SNAPLEN = 1;
const int PROMISC = 1000;
const u_int ETH_HDR_LEN = 14;
const u_int UDP_HDR_LEN = 8;

extern std::unordered_map<std::string, int> result_map;

/**
 * All types of return codes.
 */
enum RetCode {
    RET_ARGS_ERR = 10,    // invalid command line options
    RET_PCAP_ERR = 20,    // invalid pcap file
    RET_DNS_ERR = 30,
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

/**
 * Handle signals.
 */
void signal_handler(int sig);

/**
 * Reverse bits in a byte.
 */
u_char reverse_bits(u_char byte);

/**
 * Convert binary data to '%Y-%m-%d %H:%M:%S' time format and return it as a string.
 */
std::string bin_to_time(u_int32_t time);

/**
 * Convert binary data to hexadecimal format and return it as a string.
 */
std::string bin_to_hexa(u_char *data, u_int count);

/**
 * Convert domain name in 3www6google3com format to www.google.com format and return it as a string.
 */
std::string read_domain_name(u_char *dns_hdr, u_char *dns, u_int *shift);

/**
 * Exception for arguments failures.
 */
class ArgumentException: public std::invalid_argument {
public:
    explicit ArgumentException(const std::string &message);
};

/**
 * Exception for help printing.
 */
class HelpException: public std::exception {
public:
    explicit HelpException();
};

/**
 * Exception for pcap failures.
 */
class PcapException: public std::exception {
public:
    const char *what() const noexcept override {
        return m_msg.c_str();
    }
    explicit PcapException(const std::string &msg);
private:
    std::string m_msg;
};

/**
 * Exception for DNS failures.
 */
class DnsException: public std::exception {
public:
    const char *what() const noexcept override {
        return m_msg.c_str();
    }
    explicit DnsException(const std::string &msg);
private:
    std::string m_msg;
};

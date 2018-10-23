// VUT FIT 3BIT
// ISA 2018/2019
// Project: Programovani sitove sluzby
// Variant: 2 - Export DNS informaci pomoci protokolu Syslog
// Author: Vladimir Dusek, xdusek27
// Date: 30/9/2018
// File: error.h

#pragma once

#include <exception>
#include <string>
#include <unordered_map>
#include <iostream>

/**
 * Macro for debug purpose, print debug message on stderr only if constant DEBUG is defined.
 */
#ifdef DEBUG
#define DEBUG_PRINT(x) do { std::cerr << x << std::flush; } while (0)
#else
#define DEBUG_PRINT(x) do { } while (0)
#endif

// Global constants
const int BUFFER_SIZE = 512;
const std::string FILTER_EXP = "port 53";
const std::string PROJ_NAME = "dns-export";
const int DIGEST_PRINT_LEN = 20;

// Unordered map for storing statistics
extern std::unordered_map<std::string, int> result_map;

/**
 * All types of return codes.
 */
enum RetCode {
    RET_ARGS_ERR   = 1,  // arguments failure
    RET_PCAP_ERR   = 2,  // pcap failure
    RET_SYSLOG_ERR = 3,  // syslog failure
    RET_SYS_ERR    = 9   // system error (malloc, socket, signal, etc.)
};

/**
 * Help text.
 */
const std::string HELP_TEXT =
    "dns-export is a program for sniffing DNS traffic on network interface or in pcap file.\n"
    "It filters DNS responses and goes through all answers. It recognizes domain name,\n"
    "type of DNS record and its specific data. Records with the same data are counted\n"
    "together. These statistics are being sent to the syslog server.\n"
    "Usage:\n"
    "$ ./dns-export [-r file.pcap] [-i interface] [-s syslog-server] [-t seconds] [-h]\n"
    "  -r, --resource     name of the resource .pcap file for parsing\n"
    "  -i, --interface    name of the network interface for sniffing\n"
    "  -s, --server       address of the syslog server where statistics will be sent\n"
    "  -t, --timeout      value of timeout [s], statistics will be sent every n seconds\n"
    "  -h, --help         print this help\n"
    "Exit status:\n"
    "  0  if OK\n"
    "  1  if command line arguments failure\n"
    "  2  if pcap parsing/sniffing failure (e.g. wrong name of dev/pcap file, ...)\n"
    "  3  if syslog failure (e.g. cannot connect, send, ...)\n"
    "  9  if system failure (e.g. malloc, socket, signal, ...)\n";

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
std::string bin_to_hex(u_char *data, u_int count);

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
class PcapException: public std::runtime_error {
public:
    explicit PcapException(const std::string &message);
};

/**
 * Exception for syslog failures.
 */
class SyslogException: public std::runtime_error {
public:
    explicit SyslogException(const std::string &message);
};

/**
 * Exception for system failures (malloc, socket, signal, etc.).
 */
class SystemException: public std::runtime_error {
public:
    explicit SystemException(const std::string &message);
};

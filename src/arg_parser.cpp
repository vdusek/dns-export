// VUT FIT 3BIT
// ISA 2018/2019
// Project: Programovani sitove sluzby
// Variant: 2 - Export DNS informaci pomoci protokolu Syslog
// Author: Vladimir Dusek, xdusek27
// Date: 30/9/2018
// File: arg_parser.cpp

#include <getopt.h>
#include <iostream>
#include <string>
#include "utils.h"
#include "arg_parser.h"

using namespace std;

ArgParser::ArgParser():
    m_argc(0),
    m_argv(nullptr),
    m_resource(""),
    m_interface(""),
    m_server("localhost"),
    m_timeout(60)
{
}

ArgParser::~ArgParser() = default;

void ArgParser::set_args(int argc, char **argv)
{
    m_argc = argc;
    m_argv = argv;
}

std::string ArgParser::get_resource()
{
    return m_resource;
}

std::string ArgParser::get_interface()
{
    return m_interface;
}

std::string ArgParser::get_server()
{
    return m_server;
}

u_int ArgParser::get_timeout()
{
    return m_timeout;
}

void ArgParser::debug_print()
{
    DEBUG_PRINT("Configuration:\n");
    DEBUG_PRINT("    resource = " + m_resource + "\n");
    DEBUG_PRINT("    interface = " + m_interface + "\n");
    DEBUG_PRINT("    server = " + m_server + "\n");
    DEBUG_PRINT("    timeout = " + to_string(m_timeout) + "\n\n");
}

void ArgParser::parse()
{
    if (m_argc > 8) {
        throw ArgumentException("invalid combination of arguments\n"
            "Try 'dns-export --help' for more information\n");
    }

    struct option long_options[] = {
        {"resource", required_argument, nullptr, 'r'},
        {"interface", required_argument, nullptr, 'i'},
        {"server", required_argument, nullptr, 's'},
        {"timeout", required_argument, nullptr, 't'},
        {"help", no_argument, nullptr, 'h'},
        {nullptr, 0, nullptr, 0}
    };

    size_t idx;
    int opt;
    bool r_set = false,
         i_set = false,
         s_set = false,
         t_set = false;
    opterr = 0; // turn off getopt messages

    while ((opt = getopt_long(m_argc, m_argv, "r:i:s:t:h", long_options, nullptr)) != EOF) {
        switch (opt) {
            case 'r':
                if (r_set)
                    throw ArgumentException("multiple argument error\n"
                        "Try 'dns-export --help' for more information\n");
                r_set = true;
                m_resource = string(optarg);
                break;

            case 'i':
                if (i_set)
                    throw ArgumentException("multiple argument error\n"
                        "Try 'dns-export --help' for more information\n");
                i_set = true;
                m_interface = string(optarg);
                break;

            case 's':
                if (s_set)
                    throw ArgumentException("multiple argument error\n"
                        "Try 'dns-export --help' for more information\n");
                s_set = true;
                m_server = string(optarg);
                break;

            case 't':
                if (t_set)
                    throw ArgumentException("multiple argument error\n"
                        "Try 'dns-export --help' for more information\n");
                t_set = true;
                try {
                    m_timeout = static_cast<u_int>(stoi(optarg, &idx, 10));
                }
                catch (exception &exc) {
                    throw ArgumentException("invalid timeout value\n"
                        "Try 'dns-export --help' for more information\n");
                }
                if (idx != string(optarg).length()) {
                    throw ArgumentException("invalid timeout value\n"
                        "Try 'dns-export --help' for more information\n");
                }
                break;

            case 'h':
                throw HelpException();

            case '?':
                throw ArgumentException("invalid argument\n"
                    "Try 'dns-export --help' for more information\n");

            default:
                throw ArgumentException("unexpected error during parsing arguments\n"
                    "Try 'dns-export --help' for more information\n");
        }
    }

    if (m_argv[optind] != nullptr) {
        throw ArgumentException("invalid argument\n"
            "Try 'dns-export --help' for more information\n");
    }

    if (r_set && i_set) {
        throw ArgumentException("invalid combination of arguments\n"
            "Try 'dns-export --help' for more information\n");
    }

    if (r_set && t_set) {
        throw ArgumentException("invalid combination of arguments\n"
            "Try 'dns-export --help' for more information\n");
    }

    if (!r_set && !i_set) {
        throw ArgumentException("interface or resource have to be set\n"
            "Try 'dns-export --help' for more information\n");
    }
}

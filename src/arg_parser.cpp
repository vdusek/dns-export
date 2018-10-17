// VUT FIT 3BIT
// ISA 2018/2019
// Project: Programovani sitove sluzby
// Variant: 2 - Export DNS informaci pomoci protokolu Syslog
// Author: Vladimir Dusek, xdusek27
// Date: 30/9/2018
// File: config.cpp

#include <getopt.h>
#include <iostream>
#include "utils.h"
#include "arg_parser.h"

using namespace std;

ArgParser::ArgParser(int argc, char **argv):
    m_argc(argc),
    m_argv(argv),
    m_resource(""),
    m_interface(""),
    m_server(""),
    m_timeout(60)
{
}

ArgParser::~ArgParser() = default;

std::string ArgParser::resource()
{
    return m_resource;
}

std::string ArgParser::interface()
{
    return m_interface;
}

std::string ArgParser::server()
{
    return m_server;
}

u_int ArgParser::timeout()
{
    return m_timeout;
}

void ArgParser::print()
{
    cerr << "Configuration:" << endl;
    cerr << "    resource = " << m_resource << endl;
    cerr << "    interface = " << m_interface << endl;
    cerr << "    server = " << m_server << endl;
    cerr << "    timeout = " << m_timeout << endl;
    cerr << endl;
}

void ArgParser::parse()
{
    if (m_argc > 8) {
        throw ArgumentException("invalid combination of arguments\n"
            "Try 'dns-export --help' for more information.");
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
                        "Try 'dns-export --help' for more information.");
                r_set = true;
                m_resource = string(optarg);
                break;

            case 'i':
                if (i_set)
                    throw ArgumentException("multiple argument error\n"
                        "Try 'dns-export --help' for more information.");
                i_set = true;
                m_interface = string(optarg);
                break;

            case 's':
                if (s_set)
                    throw ArgumentException("multiple argument error\n"
                        "Try 'dns-export --help' for more information.");
                s_set = true;
                m_server = string(optarg);
                break;

            case 't':
                if (t_set)
                    throw ArgumentException("multiple argument error\n"
                        "Try 'dns-export --help' for more information.");
                t_set = true;
                try {
                    m_timeout = static_cast<u_int>(stoi(optarg, &idx, 10));
                }
                catch (exception &exc) {
                    throw ArgumentException("invalid timeout value\n"
                        "Try 'dns-export --help' for more information.");
                }
                if (idx != string(optarg).length()) {
                    throw ArgumentException("invalid timeout value\n"
                        "Try 'dns-export --help' for more information.");
                }
                break;

            case 'h':
                throw HelpException();

            case '?':
                throw ArgumentException("invalid argument\n"
                    "Try 'dns-export --help' for more information.");

            default:
                throw ArgumentException("unexpected error during parsing arguments\n"
                    "Try 'dns-export --help' for more information.");
        }
    }

    if (m_argv[optind] != nullptr) {
        throw ArgumentException("invalid argument\n"
            "Try 'dns-export --help' for more information.");
    }

    if (r_set && i_set) {
        throw ArgumentException("invalid combination of arguments\n"
            "Try 'dns-export --help' for more information.");
    }

    if (r_set && t_set) {
        throw ArgumentException("invalid combination of arguments\n"
            "Try 'dns-export --help' for more information.");
    }

    if (!r_set && !i_set) {
        throw ArgumentException("interface or resource have to be set\n"
            "Try 'dns-export --help' for more information.");
    }

    if (!s_set) {
        throw ArgumentException("syslog server has to be set\n"
            "Try 'dns-export --help' for more information.");
    }
}

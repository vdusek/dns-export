// VUT FIT 3BIT
// ISA 2018/2019
// Project: Programovani sitove sluzby
// Variant: 2 - Export DNS informaci pomoci protokolu Syslog
// Author: Vladimir Dusek, xdusek27
// Date: 30/9/2018
// File: config.cpp

#include <iostream>
#include <stdexcept>
#include <getopt.h>
#include "utils.h"
#include "arg_parser.h"

using namespace std;

ArgParser::ArgParser():
    resource(""),
    interface(""),
    server(""),
    timeout(60),
    help(false)
{
}

ArgParser::~ArgParser()
{
}

std::string ArgParser::get_resource()
{
    return this->resource;
}

std::string ArgParser::get_interface()
{
    return this->interface;
}

std::string ArgParser::get_server()
{
    return this->server;
}

int ArgParser::get_timeout()
{
    return this->timeout;
}

bool ArgParser::get_help()
{
    return this->help;
}

void ArgParser::print()
{
    cerr << "Configuration:" << endl;
    cerr << "    resource = " << this->resource << endl;
    cerr << "    interface = " << this->interface << endl;
    cerr << "    server = " << this->server << endl;
    cerr << "    timeout = " << this->timeout << endl;
    cerr << "    help = " << this->help << endl;
    cerr << endl;
}

void ArgParser::parse(int argc, char **argv)
{
    if (argc > 10)
        throw ArgumentException("invalid argument\n"
            "Try 'dns-export --help' for more information.");

    struct option long_options[] =
    {
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
         t_set = false,
         h_set = false;
    opterr = 0; // turn off getopt messages

    while ((opt = getopt_long(argc, argv, "r:i:s:t:h", long_options, nullptr)) != EOF) {
        switch (opt) {
            case 'r':
                if (r_set)
                    throw ArgumentException("multiple argument error\n"
                        "Try 'dns-export --help' for more information.");
                r_set = true;
                this->resource = string(optarg);
                break;

            case 'i':
                if (i_set)
                    throw ArgumentException("multiple argument error\n"
                        "Try 'dns-export --help' for more information.");
                i_set = true;
                this->interface = string(optarg);
                break;

            case 's':
                if (s_set)
                    throw ArgumentException("multiple argument error\n"
                        "Try 'dns-export --help' for more information.");
                s_set = true;
                this->server = string(optarg);
                break;

            case 't':
                if (t_set)
                    throw ArgumentException("multiple argument error\n"
                        "Try 'dns-export --help' for more information.");
                t_set = true;
                try {
                    this->timeout = stoi(optarg, &idx, 10);
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
                if (h_set)
                    throw ArgumentException("multiple argument error\n"
                        "Try 'dns-export --help' for more information.");
                h_set = true;
                this->help = true;
                break;

            case '?':
                throw ArgumentException("invalid argument\n"
                    "Try 'dns-export --help' for more information.");

            default:
                throw ArgumentException("unexpected error during parsing arguments\n"
                    "Try 'dns-export --help' for more information.");
        }
    }

    if (argv[optind] != nullptr) {
        throw ArgumentException("invalid argument\n"
            "Try 'dns-export --help' for more information.");
    }
}

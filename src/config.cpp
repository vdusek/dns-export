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
#include "error.h"
#include "config.h"

using namespace std;

Config::Config():
    resource(nullptr),
    interface(nullptr),
    server(nullptr),
    timeout(60),
    help(false)
{
}

Config::~Config()
{
}

char *Config::get_resource()
{
    return this->resource;
}

char *Config::get_interface()
{
    return this->interface;
}

char *Config::get_server()
{
    return this->server;
}

int Config::get_timeout()
{
    return this->timeout;
}

bool Config::get_help()
{
    return this->help;
}

void Config::print_help()
{
    cout << HELP_TEXT << endl;
}

void Config::print_arguments()
{
    cerr << "##### CONFIGURATION #####" << endl;
    if (resource == nullptr)
        cerr << "resource = 'nullptr'" << endl;
    else
        cerr << "resource = " << this->resource << endl;
    if (interface == nullptr)
        cerr << "interface = 'nullptr'" << endl;
    else
        cerr << "interface = " << this->interface << endl;
    if (server == nullptr)
        cerr << "server = 'nullptr'" << endl;
    else
        cerr << "server = " << this->server << endl;
    cerr << "timeout = " << this->timeout << endl;
    if (help)
        cerr << "help = 'true'" << endl;
    else
        cerr << "help = 'false'" << endl;
    cerr << "#########################" << endl;
}

void Config::parse_arguments(int argc, char *argv[])
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

    while ((opt = getopt_long(argc, argv, "r:i:s:t:h", long_options, nullptr)) != EOF) {
        switch (opt) {
            case 'r':
                if (r_set)
                    throw ArgumentException("multiple argument error\n"
                        "Try 'dns-export --help' for more information.");
                r_set = true;
                this->resource = optarg;
                break;

            case 'i':
                if (i_set)
                    throw ArgumentException("multiple argument error\n"
                        "Try 'dns-export --help' for more information.");
                i_set = true;
                this->interface = optarg;
                break;

            case 's':
                if (s_set)
                    throw ArgumentException("multiple argument error\n"
                        "Try 'dns-export --help' for more information.");
                s_set = true;
                this->server = optarg;
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
                throw ArgumentException("unexpected error\n"
                    "Try 'dns-export --help' for more information.");
        }
    }

    if (argv[optind] != nullptr) {
        throw ArgumentException("invalid argument\n"
            "Try 'dns-export --help' for more information.");
    }
}

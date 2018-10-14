// VUT FIT 3BIT
// ISA 2018/2019
// Project: Programovani sitove sluzby
// Variant: 2 - Export DNS informaci pomoci protokolu Syslog
// Author: Vladimir Dusek, xdusek27
// Date: 30/9/2018
// File: error.cpp

#include "utils.h"
#include <iostream>
#include <string>
#include <signal.h>
#include "pcap_parser.h"

using namespace std;


void print_help()
{
    cout << HELP_TEXT << endl;
}

void error(RetCode ret_code, string message)
{
    cerr << message << endl;
    exit(ret_code);
}

void signal_handler(int sig)
{
    switch (sig) {
        case SIGALRM:
            pcap_breakloop(handle);
            break;
        case SIGUSR1:
            for (const auto &elem : result_map) {
                cout << elem.first << elem.second << endl;
            }
            break;
    }
}

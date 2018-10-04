// VUT FIT 3BIT
// ISA 2018/2019
// Project: Programovani sitove sluzby
// Variant: 2 - Export DNS informaci pomoci protokolu Syslog
// Author: Vladimir Dusek, xdusek27
// Date: 30/9/2018
// File: main.cpp

#include <iostream>
#include <string>
#include "error.h"
#include "config.h"

using namespace std;

int main(int argc, char *argv[])
{
    Config cfg;
    try {
        cfg.parse_arguments(argc, argv);
    }
    catch (ArgumentException &exc) {
        error(RET_INV_OPTS, "dns-export: " + string(exc.what()));
    }

    // Debug
    cfg.print_arguments();

    if (cfg.get_help()) {
        cfg.print_help();
        return 0;
    }

    // ToDo

    // ToDo - nastavit IDE, vsechny bile znaky jako mezera (space)

    return 0;
}

// VUT FIT 3BIT
// ISA 2018/2019
// Project: Programovani sitove sluzby
// Variant: 2 - Export DNS informaci pomoci protokolu Syslog
// Author: Vladimir Dusek, xdusek27
// Date: 30/9/2018
// File: error.cpp

#include "error.h"
#include <iostream>
#include <string>

using namespace std;

void error(Ret_code ret_code, string message)
{
    cerr << message << endl;
    exit(ret_code);
}

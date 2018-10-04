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
enum Ret_code {
    RET_INV_OPTS = 1,   // invalid command line options
    RET_SYS = 2         // system error (malloc, socket, etc.)
};

/**
 * Print error message on stderr and exit the program according
 * to the ret_code parameter.
 */
void error(Ret_code ret_code, std::string message);

/**
 * For arguments failures.
 */
class ArgumentException: public std::invalid_argument {
public:
    ArgumentException(std::string const &message): std::invalid_argument(message) {}
};


# VUT FIT 3BIT
# ISA 2018/2019
# Project: Programovani sitove sluzby
# Variant: 2 - Export DNS informaci pomoci protokolu Syslog
# Author: Vladimir Dusek, xdusek27
# Date: 30/9/2018
# File: Makefile

# Usage:
#   $ make              # Compile project
#   $ make debug        # Compile project with debug purpose
#   $ make clean        # Remove object files and deplist
#   $ make clean-all    # Remove object files, deplist and binaries

CPPC = g++
CPPFLAGS = -std=c++17 -Wall -Wextra -Wpedantic -lpcap
DEPS = dep.list
SRC = main.cpp arg_parser.cpp utils.cpp pcap_parser.cpp dns_parser.cpp syslog.cpp
OBJ = $(SRC:.cpp=.o)
EXEC = dns-export

.PHONY: all exec debug clean clean-all

all: exec

debug: CPPFLAGS += -D DEBUG -g
debug: exec

exec: $(DEPS) $(EXEC)

%.o : %.cpp
	$(CPPC) $(CPPFLAGS) -c $<

$(DEPS): $(SRC)
	$(CPPC) -MM $(SRC) > $(DEPS)

-include $(DEPS)

$(EXEC): $(OBJ)
	$(CPPC) $(CPPFLAGS) $^ -o $@

clean:
	rm -f $(OBJ) $(DEPS)

clean-all:
	rm -f $(OBJ) $(DEPS) $(EXEC)

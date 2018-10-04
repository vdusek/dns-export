# VUT FIT 3BIT
# ISA 2018/2019
# Project: Programovani sitove sluzby
# Variant: 2 - Export DNS informaci pomoci protokolu Syslog
# Author: Vladimir Dusek, xdusek27
# Date: 30/9/2018
# File: Makefile

# Usage:
#   $ make
#   $ make clean
#   $ make clean-all
#   $ make pack

# -g flag for purpose of debugging
CPPC = g++
CPPFLAGS = -std=c++17 -Wall -Wextra -Wpedantic
DEPS = dep.list
SRC = main.cpp config.cpp error.cpp
H = config.h error.h
OBJ = $(SRC:.cpp=.o)
EXEC = dns-export
ARCHIVE = xdusek27.zip

.PHONY: all clean clean-all pack

all: $(DEPS) $(EXEC)

%.o : %.cpp
	$(CPPC) $(CPPFLAGS) -c $<

$(DEPS): $(SRC)
	$(CPPC) -MM $(SRC) > $(DEPS)

-include $(DEPS)

$(EXEC): $(OBJ)
	$(CPPC) $(CPPFLAGS) $^ -o $@

clean:
	rm -f $(OBJ) $(DEPS)

# add $(ARCHIVE)
clean-all:
	rm -f $(OBJ) $(DEPS) $(EXEC)

pack:
	zip $(ARCHIVE) $(SRC) $(H) Makefile

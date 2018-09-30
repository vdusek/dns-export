# VUT FIT 3BIT
# ISA 2018/2019
# Project: Programming Network Service
# Author: Vladimir Dusek, xdusek27
# Date: 30/9/2018
# File: Makefile

# Usage:
#   $ make
#   $ make clean
#   $ make clean-all

ASSIGNMENT = isa-assignment

.PHONY: all clean clean-all

all:
	pdflatex $(ASSIGNMENT).tex
	pdflatex $(ASSIGNMENT).tex

clean:
	-rm -f $(ASSIGNMENT).aux $(ASSIGNMENT).log

clean-all:
	-rm -f $(ASSIGNMENT).aux $(ASSIGNMENT).log $(ASSIGNMENT).pdf

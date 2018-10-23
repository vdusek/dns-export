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

NAME = isa-doc

.PHONY: all clean clean-all

all:
	pdflatex $(NAME).tex
	pdflatex $(NAME).tex

clean:
	-rm -f $(NAME).aux $(NAME).log $(NAME).toc

clean-all:
	-rm -f $(NAME).aux $(NAME).log $(NAME).toc $(NAME).pdf

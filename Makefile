#
# Linux Makefile.
#
# Copyright (c) 2016, CodeWard.org
#
all:
	$(MAKE) -C src/

install:
	$(MAKE) -C src/ install

uninstall:
	$(MAKE) -C src/ uninstall

clean:
	$(MAKE) -C src/ clean


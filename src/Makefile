#
# Linux Makefile.
#
# Copyright (c) 2016, CodeWard.org
#
.PHONY: all clean install uninstall
OBJECTS = main.o lscript_list.o pathname.o flist.o
TARGET = capdiss

INSTALL_PATH = /usr/local/bin

LUA_VER = 5.2

ifdef USE_LUA
LUA_VER = $(USE_LUA)
endif

CFLAGS = -O2 -pedantic -ggdb -Wall -I/usr/include/lua$(LUA_VER)
LDFLAGS = -lpcap -llua$(LUA_VER)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $^ -o $(TARGET) $(LDFLAGS)
ifdef STRIPPED
	strip $(TARGET)
endif

main.o: main.c
	$(CC) $(CFLAGS) -c $^

lscript_list.o: lscript_list.c
	$(CC) $(CFLAGS) -c $^

pathname.o: pathname.c
	$(CC) $(CFLAGS) -c $^

flist.o: flist.c
	$(CC) $(CFLAGS) -c $^

install:
	install --mode 0755 $(TARGET) $(INSTALL_PATH)

uninstall:
	rm -f $(INSTALL_PATH)/$(TARGET)

clean:
	rm -f $(TARGET) *.o


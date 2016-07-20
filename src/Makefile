#
# Linux Makefile.
#
# Copyright (c) 2016, CodeWard.org
#
OBJECTS = main.o lscript_list.o pathname.o flist.o
TARGET = capdiss

INSTALL_PATH = /usr/local/bin

CFLAGS = -O2 -pedantic -ggdb -Wall
LDFLAGS = -lpcap

ifdef LUA_STATIC
OBJECTS += ./vendor/lib/linux/liblua.a
CFLAGS += -I ./vendor/include/linux
LDFLAGS += -lm -ldl
else
LDFLAGS += -llua
endif

.PHONY: all clean install uninstall

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


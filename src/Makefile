CFLAGS = -O2 -pedantic -ggdb -Wall
LDFLAGS = -lpcap -llua

INSTALL_PATH = /usr/local/bin
TARGET = capdiss

.DUMMY: clean install

all: $(TARGET)

$(TARGET): main.o lscript_list.o pathname.o
	$(CC) $(CFLAGS) $^ -o $(TARGET) $(LDFLAGS)

main.o: main.c
	$(CC) $(CFLAGS) -c $^

lscript_list.o: lscript_list.c
	$(CC) $(CFLAGS) -c $^

pathname.o: pathname.c
	$(CC) $(CFLAGS) -c $^

install:
	install --mode 0755 $(TARGET) $(INSTALL_PATH)

uninstall:
	rm -f $(INSTALL_PATH)/$(TARGET)

clean:
	rm -f $(TARGET) *.o


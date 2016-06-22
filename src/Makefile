CC = gcc
CFLAGS = -O2 -ggdb -Wall
NAME = capdiss

.DUMMY: clean install

all: $(NAME)

$(NAME): main.o lscript_list.o capdiss_lua.o pathname.o
	$(CC) $(CFLAGS) $^ -o $(NAME) -lpcap -llua

main.o: main.c
	$(CC) $(CFLAGS) -c $^

lscript_list.o: lscript_list.c
	$(CC) $(CFLAGS) -c $^

capdiss_lua.o: capdiss_lua.c
	$(CC) $(CFLAGS) -c $^

pathname.o: pathname.c
	$(CC) $(CFLAGS) -c $^

install: $(NAME)
	install --mode 0755 $(NAME) /usr/local/bin

clean:
	rm -f $(NAME) *.o


CC = gcc
CFLAGS = -O2 -ggdb -Wall
NAME = capdiss

.DUMMY: clean install

all: $(NAME)

$(NAME): main.o scriptenv.o
	$(CC) $(CFLAGS) $^ -o $(NAME) -lpcap -llua

main.o: main.c
	$(CC) $(CFLAGS) -c $^

scriptenv.o: scriptenv.c
	$(CC) $(CFLAGS) -c $^

install:
	install --mode 0755 $(NAME) /usr/local/bin

clean:
	rm -f $(NAME) *.o


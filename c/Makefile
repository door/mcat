all: server

CFLAGS = -W -Wall -std=gnu99

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

server: server.o utils.o
	gcc -o $@ -W -Wall $^ -lpthread -lmicrohttpd -lcrypto

clean:
	rm -f *~ *.o server

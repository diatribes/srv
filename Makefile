CC = gcc
CFLAGS = -std=c89 -pedantic -Wall -Wshadow -Wpointer-arith -Wcast-qual \
         -Wstrict-prototypes -Wmissing-prototypes -Wdeclaration-after-statement \
         -Wextra

CFILES = srv.c

srv: $(CFILES) clean
	$(CC) $(CFLAGS) -o srv -pthread -O3 -DNDEBUG $(CFILES)

tcc: $(CFILES) clean
	tcc -o srv -D_REENTRANT -lpthread $(CFILES)

debug: $(CFILES) clean
	$(CC) $(CFLAGS) -o srv -pthread -g -DDEBUG $(CFILES)

prof: $(CFILES) clean
	$(CC) $(CFLAGS) -o srv -pthread -pg $(CFILES)

clean:
	rm -f srv

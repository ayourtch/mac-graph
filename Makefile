CC = gcc
CFLAGS = -g -I./lua-5.1.4/src #-O -Wall -Werror
LDFLAGS = -L./lua-5.1.4/src
LIBS = -llua -lm -lpcap # -lsocket -lnsl


all: mac-parser

lua-5.1.4.tar.gz: 
	wget http://www.lua.org/ftp/lua-5.1.4.tar.gz

lua-5.1.4/src/lua: lua-5.1.4.tar.gz
	tar xzvf lua-5.1.4.tar.gz
	(cd lua-5.1.4; make posix)


mac-parser: lua-5.1.4/src/lua mac-parser.o
	$(CC) $(LDFLAGS) -o mac-parser mac-parser.o $(LIBS)

.c.o:
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f mac-parser *.o *~ core *.core
	rm -rf lua-5.1.4


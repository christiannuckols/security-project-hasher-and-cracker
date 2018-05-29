CC	= g++ -ldl -pthread -lssl -lcrypto -I${HOME}/usr/local/ssl/include -L${HOME}/usr/local/ssl/lib

DEBUG  = -g
all: query crack fill

query:	query.o
	$(CC) -o query query.o

crack:	crack.o
	$(CC) -o crack crack.o

fill:	fill.o
	$(CC) -o fill fill.o

query.o:	query.cpp myUtility.h
	$(CC) -c query.cpp

crack.o:	crack.cpp myUtility.h
	$(CC) -c crack.cpp

fill.o:		fill.cpp myUtility.h
	$(CC) -c fill.cpp

clean:
	rm -f *.o passwdmd5 passwdSHA256 passwdSHA256salt

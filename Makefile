
CC=g++
CFLAGS=-Wall -ggdb3

all: berfilter

OBJS += berfilter.o

berfilter: $(OBJS)
	$(CC) $(OBJS) -o berfilter

test: berfilter
	@sh runtest.sh

.cc.o:
	$(CC) $(CFLAGS) -c $*.cc

clean:
	rm -f berfilter *.o


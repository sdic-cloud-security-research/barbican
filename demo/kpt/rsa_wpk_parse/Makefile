CC=gcc
CFLAGS=-g -O0
OPENSSL_ROOT=../openssl-1.1.0j/.openssl
OPENSSL_INC=$(OPENSSL_ROOT)/include
OPENSSL_LIB=$(OPENSSL_ROOT)/lib

INCS=-I $(OPENSSL_INC)
LIBS=$(OPENSSL_LIB)
SRCS=rsa_wpk_parse.c rsa_wpk_parse.h
OBJS=rsa_wpk_parse.o
EXEC=rsa_wpk_parse

all:$(OBJS)
	$(CC) -o $(EXEC) $(OBJS) $(LIBS)/libssl.a $(LIBS)/libcrypto.a -ldl -lpthread
$(OBJS):$(SRCS)
	$(CC) $(CFLAGS) -c $(INCS) $(SRCS)
clean:
	rm -f $(OBJS) $(EXEC) *.gch

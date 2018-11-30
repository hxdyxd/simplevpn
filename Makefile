
CC= gcc
CLIENT_OBJFILE = simplevpn-client
SWITCH_OBJFILE = simplevpn-switch
OBJTEST = crypto_test
FILE_LIST = ./src/crypto.c

LIBS = -lsodium


all:
	$(CC) -o $(CLIENT_OBJFILE) -I./src $(FILE_LIST) ./src/tap_client.c $(LIBS)
	$(CC) -o $(SWITCH_OBJFILE) -I./src $(FILE_LIST) ./src/cache_table.c ./src/switch.c $(LIBS)

testcrypto:
	$(CC) -o $(OBJTEST) ./src/crypto.c ./test/$(OBJTEST).c -I./src $(LIBS)
	./$(OBJTEST)

clean:
	rm -f $(OBJFILE)

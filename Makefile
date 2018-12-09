
CC= gcc
CLIENT_OBJFILE = simplevpn-client
SWITCH_OBJFILE = simplevpn-switch
OBJTEST = crypto_test
FILE_LIST = ./src/crypto.c ./src/cache_table.c
SWITCH_FILE_LIST = $(FILE_LIST) ./src/switch.c

LIBS = -lsodium

LIB_DIR = -L./libsodium-win32/lib

INC_DIR = -I./src \
-I./libsodium-win32/include

all:
	$(CC) -o $(CLIENT_OBJFILE) -I./src $(FILE_LIST) ./src/tap_client.c $(LIBS)
	$(CC) -o $(SWITCH_OBJFILE) $(SWITCH_FILE_LIST) $(LIBS)

win:
	$(CC) -o $(SWITCH_OBJFILE) $(LIB_DIR) $(INC_DIR) $(SWITCH_FILE_LIST) $(LIBS)

#wins:
#	$(CC) -Wl,-static -static -static-libgcc -o $(SWITCH_OBJFILE) $(LIB_DIR) $(INC_DIR) $(SWITCH_FILE_LIST) $(LIBS)

testall:
	$(CC) -o $(OBJTEST) ./src/crypto.c ./test/$(OBJTEST).c -I./src $(LIBS)
	./$(OBJTEST)

clean:
	rm -f $(OBJTEST) $(CLIENT_OBJFILE) $(SWITCH_OBJFILE) $(SWITCH_OBJFILE).exe

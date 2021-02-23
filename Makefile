ARGS = -lssl -lcrypto -Wall --pedantic
all: build/client build/server
	@echo -e "\033[1;32mOK\033[m"
build/client: build/encryption.o client/c_minitalk.c client/client.h
	gcc $(ARGS) build/encryption.o client/c_minitalk.c -o build/client 
build/server:	build/encryption.o server/s_minitalk.c server/server.h build/client_handling.o
	gcc $(ARGS) build/encryption.o build/client_handling.o server/s_minitalk.c -o build/server 
build/client_handling.o: server/client_handling.c server/client_handling.h
	gcc $(ARGS) -c server/client_handling.c -o build/client_handling.o
build/encryption.o: encryption.h encryption.c sc_config.h
	gcc $(ARGS) -c encryption.c -o build/encryption.o
clean:
	rm build/encryption.o build/server build/client build/client_handling.o


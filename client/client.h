#ifndef CLIENT_H
#define CLIENT_H

#include "../sc_config.h"
#include "../encryption.h"

#define NUMBER_FD 2


typedef struct client {
    int socket;
    RSA *mykeys;
    RSA *server_public_key;
} Client;

static void reset_revents(struct pollfd *fds, int size);
static void print_message(char *from, char *plain_text);
static int send_encrypted_message(Client *client, char *message);
static int print_encrypted_message(Client *client, unsigned char *encrypted, int size);
static int connect_with_server(Client *client);
static int exchange_keys(Client *client);
static void init_fds(int server_socket, struct pollfd fds[NUMBER_FD]);
static void main_loop(Client *client);
static void signal_handler(int signal);

#endif
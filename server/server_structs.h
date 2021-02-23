#ifndef SERVER_STRUCTS_H
#define SERVER_STRUCTS_H

#include "../sc_config.h"
#include "../encryption.h"

typedef struct client
{
    int fd;
    char login[MAX_LOGIN];
    RSA *public_key;
} Client;

typedef struct server
{
    int listening_socket;
    int active_clients;
    struct client clients[MAX_CLIENTS];
    RSA *mykeys;
} Server;

#endif
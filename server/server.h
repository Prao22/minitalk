#ifndef SERVER_H
#define SERVER_H

#include "../sc_config.h"
#include "../encryption.h"
#include "server_structs.h"
#include "client_handling.h"


static void signal_handler(int signal);
static void reset_revents(struct pollfd *fds);

static int create_listening_socket(Server *server);
static void exchange_keys(Server *server, int id_server, int id_fds, struct pollfd *fds);
static void accept_new_client(Server *server, struct pollfd *fds);
static void disconnect_with(Server *server, struct pollfd *fds, int id_server, int id_fds);
static void disconnect_with_all(Server* server);

static void handle_login_set(Server *server, Client *client, unsigned char *message, int size);
static void handle_disconection(Server *server, int id_server, int id_fds, struct pollfd *fds);
static void handle_clients(Server *server, struct pollfd *fds, int how_many);


#endif
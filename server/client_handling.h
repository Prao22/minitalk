#ifndef CLIENT_HANDLING_H
#define CLIENT_HANDLING_H

#include "server_structs.h"
#include "../encryption.h"

int fd2id(Server *server, int fd);
int read_login(Server *server, char *login, unsigned char *message, int size);
int validate_login(char *login);
int send_encrypted_message(char *plain_text, struct client *to);
void send_greetings(Server* server, Client *client);
void send_to_all(Server* server, char *message);
void redirect_message(Server *server, unsigned char *message, int size, Client *from);

#endif
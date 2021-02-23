#ifndef SC_CONFIG_H
#define SC_CONFIG_H

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>

#define RSA_BITS 2048
#define AES_KEY_LEN 32
#define AES_IV_LEN 16
#define AES_BLOCK_SIZE 16
#define RSA_ENCRYPTED_LEN (RSA_BITS / 8)

#define localIPv4 "127.0.0.1"
#define PORT 59001
#define MAX_CLIENTS 10
#define MAX_LOGIN 16
#define BACKLOG 10
#define TIME_OUT 1000
#define MAX_MESSAGE_LEN 2048
#define ALL_FD "*"

#define MAX_PLAIN_TEXT (MAX_MESSAGE_LEN - RSA_ENCRYPTED_LEN - AES_IV_LEN - AES_BLOCK_SIZE)
#define SERVER_LOGIN "Server"

#endif
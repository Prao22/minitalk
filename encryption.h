#ifndef ENCRYPTION_H
#define ENCRYPTION_H
#include "sc_config.h"

#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

int encode_AES(unsigned char aes_iv[], unsigned char aes_key[], char *plain_text, unsigned char *encrypted);
int decode_AES(unsigned char aes_iv[], unsigned char aes_key[], unsigned char *encrypted, int en_size, char *plain_text);
int encrypt_message(char *plain_text, char *login, unsigned char *encrypted, RSA *key);
int decrypt_message(unsigned char *encrypted, int size, char *login, char *plain_text, RSA* keys);

int create_RSA(RSA** keys);
void delete_RSA(RSA** keys);

int send_public_RSA(RSA* keys, int fd);
int read_public_RSA(RSA** keys, int fd);

void print_RSA(RSA* keys);
void print_bytes(unsigned char* bytes, int size);
int show_openssl_err();

#endif
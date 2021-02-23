#include "client_handling.h"

static Client *login2client(Server *server, char *login);
static int get_receiver_and_key(Server *server, unsigned char *login_and_key, unsigned char *message, int size, Client **client, bool *all);
static int redirect_to(Client *to, unsigned char *login_and_key, unsigned char *message, int size);


static Client *login2client(Server *server, char *login)
{
    for (int i = 0; i < server->active_clients; i++)
    {
        if (strncmp(login, server->clients[i].login, MAX_LOGIN) == 0)
        {
            return &server->clients[i];
        }
    }

    return NULL;
}

int fd2id(Server *server, int fd)
{
    for (int i = 0; i < server->active_clients; i++)
    {
        if (server->clients[i].fd == fd)
        {
            return i;
        }
    }

    return -1;
}

static int get_receiver_and_key(Server *server, unsigned char *login_and_key, unsigned char *message, int size, Client **client, bool *all)
{
    int rsa_length = RSA_private_decrypt(RSA_ENCRYPTED_LEN, message + AES_IV_LEN, login_and_key, server->mykeys, RSA_PKCS1_PADDING);

    if (rsa_length < 1)
    {
        show_openssl_err();
        return 1;
    }

    char login_to[MAX_LOGIN];
    memcpy(login_to, login_and_key, MAX_LOGIN);

    if (strnlen(login_to, MAX_LOGIN) == MAX_LOGIN)
    {
        return 1;
    }

    if (!strncmp(login_to, ALL_FD, MAX_LOGIN))
    {
        *client = NULL;
        *all = true;
    }
    else
    {
        *client = login2client(server, login_to);
        *all = false;
    }

    return 0;
}

int read_login(Server *server, char *login, unsigned char *message, int size)
{
    char plain_text[MAX_PLAIN_TEXT];

    if (decrypt_message(message, size, login, plain_text, server->mykeys) == -1)
    {
        return 1;
    }

    strncpy(login, plain_text, MAX_LOGIN);

    return 0;
}

int validate_login(char *login)
{
    return strnlen(login, MAX_LOGIN) == MAX_LOGIN || !strncmp(login, SERVER_LOGIN, MAX_LOGIN) || strnlen(login, MAX_LOGIN) < 4;
}

int send_encrypted_message(char *plain_text, struct client *to)
{
    unsigned char encrypted[MAX_MESSAGE_LEN];
    int message_size = encrypt_message(plain_text, SERVER_LOGIN, encrypted, to->public_key);
    return write(to->fd, encrypted, message_size);
}

void send_greetings(Server* server, Client *client)
{
    char hello[MAX_MESSAGE_LEN];
    strcpy(hello, "\n\nCzesc ");
    strcat(hello, client->login);
    strcat(hello, "\n\nLista zalogowanych:\n");

    for (int i = 0; i < server->active_clients; i++)
    {
        if (server->clients[i].login[0] == '\0')
        {
            strcat(hello, "<?>\n");
        }
        else
        {
            strcat(hello, server->clients[i].login);
            strcat(hello, "\n");
        }
    }

    strcat(hello, "\nJak ma wygladac wiadomosc:\n<login> <wiadomosc>\nJesli <login> = * rozsyla do wszystkich\n\n");

    send_encrypted_message(hello, client);
}

void send_to_all(Server* server, char *message)
{
    for (int i = 0; i < server->active_clients; i++)
    {
        send_encrypted_message(message, &server->clients[i]);
    }
}

static int redirect_to(Client *to, unsigned char *login_and_key, unsigned char *message, int size)
{
    int rsa_length = RSA_public_encrypt(MAX_LOGIN + AES_KEY_LEN, login_and_key, message + AES_IV_LEN, to->public_key, RSA_PKCS1_PADDING);

    if (rsa_length < 1)
    {
        show_openssl_err();
        return 1;
    }
    write(to->fd, message, size);
    return 0;
}

void redirect_message(Server *server, unsigned char *message, int size, Client *from)
{
    unsigned char login_and_key[MAX_LOGIN + AES_KEY_LEN];

    Client *to = NULL;
    bool all = false;

    if (get_receiver_and_key(server, login_and_key, message, size, &to, &all))
    {
        send_encrypted_message("Blad", from);
        return;
    }

    if (to == NULL && !all)
    {
        send_encrypted_message("Nie ma takiego loginu!", from);
        return;
    }

    memcpy(login_and_key, from->login, MAX_LOGIN);


    if (!all)
    {
        redirect_to(to, login_and_key, message, size);
    }
    else
    {
        for (int i = 0; i < server->active_clients; i++)
        {
            if (server->clients[i].fd != from->fd && server->clients[i].public_key != NULL)
            {
                redirect_to(&server->clients[i], login_and_key, message, size);
            }
        }
    }
}
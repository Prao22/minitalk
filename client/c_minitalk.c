#include "client.h"
bool end = false;
int main()
{
    struct sigaction signal;
    signal.sa_handler = signal_handler;
    sigemptyset(&signal.sa_mask);
    signal.sa_flags = 0;

    if(sigaction(SIGINT, &signal, NULL) == -1) 
    {
        fprintf(stderr, "sigaction()\n");
        return 0;
    }


    Client *client = malloc(sizeof(Client));

    if (!create_RSA(&client->mykeys))
    {
        fprintf(stderr, "err: create_RSA()\n");
        goto RSA_ERR;
    }

    if (connect_with_server(client))
    {
        fprintf(stderr, "err: connect_with_server()\n");
        goto CONNECT_ERR;
    }

    if (exchange_keys(client))
    {
        fprintf(stderr, "err: exchange_keys()\n");
        goto EXCHANGE_ERR;
    }

    printf("Polaczono z serwerem!\n");

    main_loop(client);

EXCHANGE_ERR:
    delete_RSA(&client->server_public_key);
CONNECT_ERR:
    close(client->socket);
RSA_ERR:
    delete_RSA(&client->mykeys);
    free(client);

    return 0;
}

static void main_loop(Client *client)
{
    struct pollfd fds[NUMBER_FD];
    unsigned char message[MAX_MESSAGE_LEN];

    init_fds(client->socket, fds);

    while (!end)
    {
        memset(message, 0, MAX_MESSAGE_LEN * sizeof(char));
        int ret = poll(fds, NUMBER_FD, -1);

        if (ret > 0)
        {
            if (fds[0].revents & POLLIN)
            {
                int ret = read(fds[0].fd, message, MAX_MESSAGE_LEN);

                if (ret == 0)
                {
                    fprintf(stderr, "Rozlaczono z serwerem!\n");
                    break;
                }

                print_encrypted_message(client, message, ret);
            }

            if (fds[1].revents & POLLIN)
            {
                if (fgets((char *)message, MAX_PLAIN_TEXT, stdin) == NULL)
                {
                    fprintf(stderr, "Error stdin\n");
                    end = true;
                    break;
                }

                send_encrypted_message(client, (char *)message);
            }
        }
        else if (ret == 0)
        {
            //fprintf(stderr, ".");
        }
        else
        {
            perror("poll()");
        }

        reset_revents(fds, NUMBER_FD);
    }
}

static void signal_handler(int signal)
{
    fprintf(stderr, "\n\nKONIEC\n");
    end = true;
}

static void reset_revents(struct pollfd *fds, int size)
{
    for (int i = 0; i < size; i++)
    {
        fds[i].revents = 0;
    }
}

static void print_message(char *from, char *plain_text)
{
    printf("[%s] %s\n", from, plain_text);
}

static int send_encrypted_message(Client *client, char *message)
{
    char *space = strpbrk(message, " ");
    char *plain = message;
    char *to = message;
    
    size_t len = strlen(message);
    if (len > 0 && message[len - 1] == '\n')
    {
        message[len - 1] = '\0';
    }

    message[MAX_PLAIN_TEXT - 1] = '\0';

    if (space == NULL)
    {
        to = SERVER_LOGIN;
    }
    else
    {
        *space = '\0';
        plain = space + 1;
    }

    unsigned char encrypted[MAX_MESSAGE_LEN];
    int message_size = encrypt_message(plain, to, encrypted, client->server_public_key);
    return write(client->socket, encrypted, message_size);
}

static int print_encrypted_message(Client *client, unsigned char *encrypted, int size)
{
    char plain[MAX_MESSAGE_LEN];
    char from[MAX_LOGIN];

    if (decrypt_message(encrypted, size, from, plain, client->mykeys) <= 0)
    {
        return 1;
    }

    print_message(from, plain);
    return 0;
}

static int connect_with_server(Client *client)
{
    client->socket = socket(AF_INET, SOCK_STREAM, 0);

    if (client->socket == -1)
    {
        perror("socket()");
        return 1;
    }

    struct sockaddr_in sn;
    struct in_addr ad;

    inet_pton(AF_INET, localIPv4, &ad.s_addr);

    sn.sin_family = AF_INET;
    sn.sin_port = PORT;
    sn.sin_addr = ad;

    return connect(client->socket, (struct sockaddr *)&sn, sizeof(sn)) == -1;
}

static int exchange_keys(Client *client)
{
    return read_public_RSA(&client->server_public_key, client->socket) || send_public_RSA(client->mykeys, client->socket);
}

static void init_fds(int server_socket, struct pollfd fds[NUMBER_FD])
{
    fds[0].fd = server_socket;
    fds[0].events = POLLIN;
    fds[0].revents = 0;

    fds[1].fd = 0;
    fds[1].events = POLLIN;
    fds[1].revents = 0;
}


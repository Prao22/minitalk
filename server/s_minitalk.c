#include "server.h"

bool end = false;

int main()
{
    struct sigaction signal;
    signal.sa_handler = signal_handler;
    sigemptyset(&signal.sa_mask);
    signal.sa_flags = 0;

    if (sigaction(SIGINT, &signal, NULL) == -1)
    {
        fprintf(stderr, "sigaction()\n");
        return 0;
    }

    fprintf(stderr, "\n--SERWER--\nCTRL+C - wyjście\n\n");
    Server server;
    server.active_clients = 0;

    if (!create_RSA(&server.mykeys))
    {
        fprintf(stderr, "create_RSA()\n");
        goto RSA_ERR;
    }

    if (create_listening_socket(&server))
    {
        fprintf(stderr, "create_listening_socket()\n");
        goto SOCKET_ERR;
    }

    struct pollfd fds[MAX_CLIENTS + 1];
    memset(fds, 0, sizeof(struct pollfd) * (MAX_CLIENTS + 1));
    fds[0].fd = server.listening_socket;
    fds[0].events = POLLIN;

    while (!end)
    {
        int ret = poll(fds, server.active_clients + 1, TIME_OUT);

        if (ret > 0)
        {
            if (fds[0].revents & POLLIN)
            {
                accept_new_client(&server, fds);
            }

            handle_clients(&server, fds, ret);
        }
        else if (ret == 0)
        {
            fprintf(stderr, ".");
        }
        else
        {
            perror("poll()");
        }

        reset_revents(fds);
    }

    disconnect_with_all(&server);
SOCKET_ERR:
    close(server.listening_socket);
RSA_ERR:
    delete_RSA(&server.mykeys);
}

static void handle_clients(Server *server, struct pollfd *fds, int how_many)
{
    for (int i = 0; i < server->active_clients && how_many > 0; i++)
    {
        if (fds[i + 1].revents & POLLIN)
        {
            //fprintf(stderr, "\nClient z fd = %d id = %d\n", i + 1, id);
            int server_id = fd2id(server, fds[i + 1].fd);
            Client *client = &server->clients[server_id];

            if (client->public_key == NULL)
            {
                exchange_keys(server, server_id, i + 1, fds);
                continue;
            }

            unsigned char message[MAX_MESSAGE_LEN];
            memset(message, 0, MAX_MESSAGE_LEN * sizeof(char));

            int ret = read(fds[i + 1].fd, message, MAX_MESSAGE_LEN);

            fprintf(stderr, "Przyjalem wiadomosc o rozmiarze %d\n", ret);

            if (ret <= 0)
            {
                handle_disconection(server, server_id, i + 1, fds);
                continue;
            }

            if (client->login[0] == '\0')
            {
                handle_login_set(server, client, message, ret);
                continue;
            }

            redirect_message(server, message, ret, client);

            how_many--;
        }
    }
}

static int create_listening_socket(Server *server)
{
    struct sockaddr_in socket_addr;
    struct in_addr address;
    server->listening_socket = socket(AF_INET, SOCK_STREAM, 0);

    if (server->listening_socket == -1)
    {
        perror("socket()");
        return 1;
    }

    inet_pton(AF_INET, localIPv4, &address.s_addr);

    socket_addr.sin_family = AF_INET;
    socket_addr.sin_port = PORT;
    socket_addr.sin_addr = address;

    if (bind(server->listening_socket, (struct sockaddr *)&socket_addr, sizeof(socket_addr)) == -1)
    {
        perror("bind()");
        return 1;
    }

    if (listen(server->listening_socket, BACKLOG) == -1)
    {
        perror("listen()");
        return 1;
    }

    return 0;
}

static void reset_revents(struct pollfd *fds)
{
    for (int i = 0; i < MAX_CLIENTS + 1; i++)
    {
        fds[i].revents = 0;
    }
}

static void accept_new_client(Server *server, struct pollfd *fds)
{
    fprintf(stderr, "\nNowy klient\n");
    int s_client = accept(server->listening_socket, NULL, NULL);

    if (s_client == -1)
    {
        perror("accept()");
        return;
    }

    if (server->active_clients >= MAX_CLIENTS)
    {
        fprintf(stderr, "\nSerwer pelny a ktos chce dolaczyc\n");
        //write(s_client, "Server Serwer pelny!", 21);
        dprintf(s_client, "Server Serwer pelny!");
        close(s_client);
        return;
    }

    if (send_public_RSA(server->mykeys, s_client))
    {
        fprintf(stderr, "send_my_pk()\n");
        return;
    }

    Client *client = &server->clients[server->active_clients];
    client->fd = s_client;
    client->login[0] = '\0';
    client->public_key = NULL;

    fds[server->active_clients + 1].fd = s_client;
    fds[server->active_clients + 1].events = POLLIN;

    server->active_clients++;
}

static void disconnect_with(Server *server, struct pollfd *fds, int id_server, int id_fds)
{
    close(server->clients[id_server].fd);

    memmove(server->clients + id_server, server->clients + id_server + 1, sizeof(struct client) * (server->active_clients - id_server));
    memmove(fds + id_fds, fds + id_fds + 1, sizeof(struct pollfd) * (server->active_clients - id_fds));
    server->active_clients--;
}

static void disconnect_with_all(Server *server)
{
    send_to_all(server, "Koniec serwera");

    for (int i = 0; i < server->active_clients; i++)
    {
        close(server->clients[i].fd);
    }
}

static void exchange_keys(Server *server, int id_server, int id_fds, struct pollfd *fds)
{
    if (read_public_RSA(&server->clients[id_server].public_key, server->clients[id_server].fd))
    {
        disconnect_with(server, fds, id_server, id_fds);
        fprintf(stderr, "Podano nie wazny klucz rozlaczam\n");
        return;
    }

    send_encrypted_message("Podaj login (max 15 znakow)", &server->clients[id_server]);
}

static void handle_login_set(Server *server, Client *client, unsigned char *message, int size)
{
    char login[MAX_LOGIN];

    if (read_login(server, login, message, size) || validate_login(login))
    {
        fprintf(stderr, "Podano nie wazny login\n");
        send_encrypted_message("Login nieprawidlowy!\nPodaj login (4 - 15 znakow)", client);
        return;
    }

    strcpy(client->login, login);

    send_greetings(server, client);

    char announcement[MAX_LOGIN + 64];
    strcpy(announcement, login);
    strcat(announcement, " dolaczyl do serwera!");
    send_to_all(server, announcement);
}

static void handle_disconection(Server *server, int id_server, int id_fds, struct pollfd *fds)
{
    char message[MAX_LOGIN + 16];
    fprintf(stderr, "\n%s rozlaczyl sie!\n", server->clients[id_server].login);

    strcpy(message, server->clients[id_server].login);
    strcat(message, " rozlaczyl sie!");

    disconnect_with(server, fds, id_server, id_fds);

    send_to_all(server, message);
}

static void signal_handler(int signal)
{
    fprintf(stderr, "\n\nKONIEC\n");
    end = true;
}

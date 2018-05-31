#include <log.h>
#include <client_s.h>
#include <common.h>
#include <stdlib.h>
#include <unistd.h>

/* helpers for List2D */
static int client_cmp(const Client *c1, const Client *c2);
static int client_cmp_wrapper(const void *c1, const void *c2);
static int client_diff(const Client *c1, const Client *c2);
static int client_diff_wrapper(const void *c1, const void *c2);
static void client_destroy_wrapper(void *client);

static int client_cmp(const Client *c1, const Client *c2)
{
    if (c1->fd < c2->fd)
        return -1;

    if (c1->fd > c2->fd)
        return 1;

    return 0;
}

static int client_cmp_wrapper(const void *c1, const void *c2)
{
    const Client *client1 = *(const Client **)c1;
    const Client *client2 = *(const Client **)c2;

    return client_cmp(client1, client2);
}

static int client_diff(const Client *c1, const Client *c2)
{
    return ABS(c1->fd - c2->fd);
}

static int client_diff_wrapper(const void *c1, const void *c2)
{
    const Client *client1 = *(const Client **)c1;
    const Client *client2 = *(const Client **)c2;

    return client_diff(client1, client2);
}

static void client_destroy_wrapper(void *client)
{
    Client *cl = *(Client **)client;
    client_destroy(cl);
}

Client *client_create(int fd, SSL *session)
{
    Client *client;

    TRACE();

    client = (Client *)malloc(sizeof(Client));
    if (client == NULL)
        ERROR("malloc error\n", NULL);

    client->fd = fd;
    client->ssl_session = session;
    client->pkey = NULL;
    message_reset(&client->msg);

    return client;
}

void client_destroy(Client *client)
{
    if (client == NULL)
        return;

    TRACE();

    SSL_free(client->ssl_session);
    BN_free(client->pkey);
    close(client->fd);
    FREE(client);
}

List2D *create_client_list2d(void)
{
    return list2d_create(sizeof(Client *), client_cmp_wrapper, client_diff_wrapper, client_destroy_wrapper);
}
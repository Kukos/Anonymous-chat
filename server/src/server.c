#include <server.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <tls_lib.h>
#include <socket_lib.h>
#include <stdlib.h>
#include <unistd.h>
#include <log.h>
#include <message.h>
#include <client_s.h>
#include <list2d.h>
#include <darray.h>
#include <sys/time.h>

#define TIMEOUT_S 1
#define TIMEOUT_US 0

#define PRIME_LEN 128

#define MAX_CLIENTS 32

#define CERT_FILE "cert.pem"
#define KEY_FILE "key.pem"

#define MESSAGE_WELCOME         "Welcome in the Anonymus server!!!\n"
#define MESSAGE_NEW_USER_JOIN   "New user has joined to chat!\n"
#define MESSAGE_USER_LEFT       "User left chat!\n"
#define MESSAGE_CURRENT_USERS   "Users: %zu\n"

/*
    Generate Diffie Hellman parameters like g and p

    PARAMS
    @IN len - prime len in bits to generate

    RETURN
    NULL iff failure
    Pointer to new DH iff success
*/
static DH *dh_generate(int len);

/*
    Destroy DH

    PARAMS
    @IN dh - dh

    RETURN
    This is a void function
*/
static void dh_destroy(DH *dh);

/*
    Update fd set with fd from ring

    PARAMS
    @IN ring - clients ring
    @IN set - fd set

    RETURN
    max fd set from ring iff success
    -1 iff failure
*/
static int fd_set_update(List2D *ring, fd_set *set);

/*
    Send message to all users in a ring

    PARAMS
    @IN ring - clients ring
    @IN msg - message to send

    RETUTRN
    This is a void function
*/
static void message_send_to_all(List2D *ring, Message *msg);

/*
    Send keys to whole ring

    PARAMS
    @IN ring - clients ring

    RETURN
    This is a void function
*/
static void send_keys(List2D *ring);

/*
    Check if all keys and set and server can send keys

    PARAMS
    @IN ring - clients ring

    RETURN
    This is a void function
*/
static bool can_send_keys(List2D *ring);

/*
    Decrypt message

    PARAMS
    @IN ring - clients ring
    @IN msg - message where will be store decryption

    RETURN
    This is a void function
*/
static void message_decrypt(List2D *ring, Message *msg);

static void send_keys(List2D *ring)
{
    Message msg;
    List2D_node *node;
    Client *client;
    Client *prev;
    Client *next;

    TRACE();

    for_each(ring, List2D, node, client)
    {
        (void)memcpy(&prev, node->____prev->____data, sizeof(Client *));
        (void)memcpy(&next, node->____next->____data, sizeof(Client *));

        message_create_left_neighbor_public_key(&msg, prev->pkey);
        if (message_send_tls(client->ssl_session, &msg))
            FATAL("Message tls send error\n");

        message_create_right_neighbor_public_key(&msg, next->pkey);
        if (message_send_tls(client->ssl_session, &msg))
            FATAL("Message tls send error\n");
    }
}

static DH *dh_generate(int len)
{
    DH *dh;

    TRACE();

    dh = DH_new();

    LOG("Generating %d bits prime\n", len);
    DH_generate_parameters_ex(dh, len, DH_GENERATOR_2, NULL);
    LOG("DH prime: %s\n", BN_bn2hex(dh->p));

    return dh;
}

static void dh_destroy(DH *dh)
{
    TRACE();

    if (dh == NULL)
        return;

    DH_free(dh);
}

static int fd_set_update(List2D *ring, fd_set *set)
{
    int max = -1;
    Client *client;

    TRACE();

    for_each_data(ring, List2D, client)
    {
        FD_SET(client->fd, set);
        max = MAX(max, client->fd);
    }

    return max;
}

static void message_send_to_all(List2D *ring, Message *msg)
{
    Client *client;

    TRACE();

    for_each_data(ring, List2D, client)
    {
        if (message_send_tls(client->ssl_session, msg))
            FATAL("send_message error\n");
    }
}

static bool can_send_keys(List2D *ring)
{
    Client *client;

    TRACE();

    for_each_data(ring, List2D, client)
    {
        if (client->pkey == NULL)
            return false;
    }

    return true;
}

static void message_decrypt(List2D *ring, Message *msg)
{
    Client *client;
    size_t i;

    TRACE();

    LOG("Decrypting msg\n");

    for_each_data(ring, List2D, client)
    {
        for (i = 0; i < MESSAGE_PAYLOAD_SIZE; ++i)
            msg->payload[i] ^= client->msg.payload[i];
    }

    msg->header.payload_size = strlen(msg->payload);
    msg->header.crc = crc64(&msg->payload[0], msg->header.payload_size);
}

void server_job(const char *host_name, int port)
{
    /* DH key */
    DH *dh;

    /* TLS */
    SSL_CTX *ctx;
    SSL *ssl;

    /* TCP */
    int server_socket;
    int fd_client;
    int max_fd;

    /* FD sets for listen / select */
    fd_set server_fd_set;
    fd_set copy;

    /* needed to work with clients */
    Message msg;
    Message msg_private;
    char buf[MESSAGE_PAYLOAD_SIZE];
    int ret;

    List2D *clients_ring;
    Client *client;

    /* state machines */
    Darray *to_delete;
    bool changes = false;
    bool can_delete = true;
    bool msg_is_decrypted = false;
    bool end_rnd = false;
    size_t recv_msg = 0;

    /* timeout for select */
    struct timeval tv;

    TRACE();

    /* generate g and p */
    dh = dh_generate(PRIME_LEN);

    /* init tls lib */
    tls_init();

    /* prepare tcp and tls server */
    ctx = tls_create_server_context(CERT_FILE, KEY_FILE);
    server_socket = tcp_create_socket(host_name, port);

    max_fd = server_socket;

	if (listen(server_socket, MAX_CLIENTS) < 0)
        FATAL("listen error\n");

	FD_ZERO(&server_fd_set);
	FD_SET(server_socket, &server_fd_set);

    /* here clients will be wroted */
    clients_ring = create_client_list2d();
    if (clients_ring == NULL)
        FATAL("List2D create error\n");

    while (1)
    {
        copy = server_fd_set;
        tv.tv_sec = TIMEOUT_S;
        tv.tv_usec = TIMEOUT_US;
        if (select(max_fd + 1, &copy, NULL, NULL, &tv) == 0)
            if ((size_t)list2d_get_num_entries(clients_ring) >= 3)
                end_rnd = true;

        /* create buffer for deletion */
        to_delete = darray_create(DARRAY_UNSORTED, 0, sizeof(Client *), NULL, NULL);
        if (to_delete == NULL)
            FATAL("darray_create error\n");

        /* new client connection */
        if (FD_ISSET(server_socket, &copy))
        {
            LOG("NEW Connection\n");

            fd_client = tcp_accept_connection(server_socket);
            ssl = tls_accept(ctx, fd_client);

            /* send welcome msg */
            (void)snprintf(buf, sizeof(buf), MESSAGE_WELCOME MESSAGE_CURRENT_USERS, (size_t)list2d_get_num_entries(clients_ring));
            message_create_info(&msg, buf);
            if (message_send_tls(ssl, &msg))
                FATAL("send_message error\n");

            /* send g and p */
            message_create_generator(&msg, dh);
            if (message_send_tls(ssl, &msg))
                FATAL("send_message error\n");

            message_create_prime(&msg, dh);
            if (message_send_tls(ssl, &msg))
                FATAL("send_message error\n");

            /* connection established, so add client to ring */
            client = client_create(fd_client, ssl);
            if (client == NULL)
                FATAL("client create error\n");

            /* send info to all users that we have another client */
            (void)snprintf(buf, sizeof(buf), MESSAGE_NEW_USER_JOIN MESSAGE_CURRENT_USERS, (size_t)list2d_get_num_entries(clients_ring) + 1);
            message_create_info(&msg, buf);
            message_send_to_all(clients_ring, &msg);

            /* new client in ring */
            list2d_insert(clients_ring, (const void *)&client);

            /* update server fd */
            max_fd = MAX(server_socket, fd_set_update(clients_ring, &server_fd_set));

            /* new client connected, state has been changed */
            changes = true;
        }
        else /* data from old clients */
        {
            /* for each client in ring */
            for_each_data(clients_ring, List2D, client)
            {
                /* have msg from client */
                if (FD_ISSET(client->fd, &copy))
                {
                    ret = message_recv_tls(client->ssl_session, &client->msg);
                    if (ret == 1)
                    {
                        LOG("Client with %d fd closed connection\n", client->fd);

                        /* buffer delete list */
                        darray_insert(to_delete, (const void *)&client);
                    }
                    else if (ret)
                    {
                        LOG("Message corrupted\n");
                    }
                    else
                    {
                        /* Correct msg */
                        switch (client->msg.header.type)
                        {
                            /* got public key, update client in ring */
                            case MESSAGE_CLIENT_PUBLIC_KEY:
                            {
                                LOG("Public key from %d fd = %s\n", client->fd, client->msg.payload);
                                BN_hex2bn(&client->pkey, client->msg.payload);
                                break;
                            }
                            /* client closed connection, add to delete list */
                            case MESSAGE_CLOSE_CONNECTION:
                            {
                                LOG("Client with %d fd closed connection\n", client->fd);

                                /* buffer delete list */
                                darray_insert(to_delete, (const void *)&client);

                                break;
                            }
                            /* server wrote msg into proper place, so just note that another user sents msg in this rnd */
                            case MESSAGE_NORMAL:
                            {
                                ++recv_msg;
                                break;
                            }
                            default:
                            {
                                LOG("Unsupported message type\n");
                                break;
                            }
                        }
                    }
                }
            }
        }

        /* watchdog expires, rnd ends, so stop delete, we need public keys */
        if (end_rnd)
        {
            LOG("ROUND ENDS\n");

            can_delete = false;

            /* send msg to all users, rnd ends */
            message_create_round_end(&msg);
            message_send_to_all(clients_ring, &msg);

            end_rnd = false;
        }

        /* everyone sents msg, decrypt it, unlock deletion and be prepare to send msg */
        if (recv_msg > 0 && recv_msg == (size_t)list2d_get_num_entries(clients_ring))
        {
            LOG("ALL msg received\n");
            recv_msg = 0;
            can_delete = true;
            msg_is_decrypted = true;

            message_create_normal(&msg_private, NULL);
            message_decrypt(clients_ring, &msg_private);
        }

        /* delete */
        if (can_delete)
        {
            for_each_data(to_delete, Darray, client)
            {
                LOG("Delete client with %d fd\n", client->fd);

                /* delete from fd */
                FD_CLR(client->fd, &server_fd_set);

                /* delete from ring */
                list2d_delete_with_entry(clients_ring, (const void *)&client);

                /* update server fd */
                max_fd = MAX(server_socket, fd_set_update(clients_ring, &server_fd_set));

                (void)snprintf(buf, sizeof(buf), MESSAGE_USER_LEFT MESSAGE_CURRENT_USERS, (size_t)list2d_get_num_entries(clients_ring));
                message_create_info(&msg, buf);
                message_send_to_all(clients_ring, &msg);
            }

            /* send keys */
            if ((size_t)darray_get_num_entries(to_delete) > 0)
                changes = true;
        }

        /* msg has been decrypted, send to all users */
        if (msg_is_decrypted)
        {
            LOG("MSG is decrypted: %s\n", msg_private.payload);
            msg_is_decrypted = false;
            message_send_to_all(clients_ring, &msg_private);
            message_reset(&msg_private);
        }

        /* ring has been changed, send keys */
        if (changes && can_send_keys(clients_ring) && (size_t)list2d_get_num_entries(clients_ring) >= 3)
        {
            LOG("Send again keys\n");
            send_keys(clients_ring);
            changes = false;
        }

        darray_destroy(to_delete);
    }

    list2d_destroy_with_entries(clients_ring);
    close(server_socket);
    tls_destroy_context(ctx);
    tls_clenup();
    dh_destroy(dh);
}
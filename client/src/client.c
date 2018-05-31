#include <client.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <tls_lib.h>
#include <socket_lib.h>
#include <stdlib.h>
#include <unistd.h>
#include <log.h>
#include <message.h>
#include <stdbool.h>
#include <crc.h>

#define CERT_FILE "cert.pem"
#define KEY_FILE "key.pem"

/*
    Encrypt an message using left and right keys

    PARAMS
    @IN msg - msg to encrypt
    @IN left - left key
    @IN right - right key

    RETURN
    This is a void function
*/
static void message_encrypt(Message *msg, const BIGNUM *left, const BIGNUM *right);

static void message_encrypt(Message *msg, const BIGNUM *left, const BIGNUM *right)
{
    size_t i;

    unsigned char buf1[BN_num_bytes(left) + 1];
    unsigned char buf2[BN_num_bytes(right) + 1];

    TRACE();

    BN_bn2bin(left, buf1);
    BN_bn2bin(right, buf2);

    LOG("Encrypt msg\n");
    for (i = 0; i < MESSAGE_PAYLOAD_SIZE; ++i)
        msg->payload[i] ^= (char)(buf1[(int)i % BN_num_bytes(left)] ^ buf2[(int)i % BN_num_bytes(right)]);

    msg->header.payload_size = MESSAGE_PAYLOAD_SIZE;
    msg->header.crc = crc64(&msg->payload[0], msg->header.payload_size);
}

void client_job(const char *host_name, int port)
{
    DH *dh;
    BIGNUM *left_pkey = NULL;
    BIGNUM *right_pkey = NULL;

    /* TLS */
    SSL_CTX *ctx;
    SSL *ssl;

    /* TCP */
    int server_fd;

    /* FD sets for listen / select */
    fd_set client_fd_set;
    fd_set copy;

    Message msg_work_with_server;
    Message msg_private;
    char buf [MESSAGE_PAYLOAD_SIZE];

    bool have_generator = false;
    bool have_prime = false;
    int ret;

    TRACE();

    dh = DH_new();

    tls_init();

    /* establish connection */
    ctx = tls_create_client_context(CERT_FILE, KEY_FILE);
    server_fd = tcp_request_connection(host_name, port);
    ssl = tls_request_connection(ctx, server_fd);

    FD_ZERO(&client_fd_set);
	FD_SET(STDIN_FILENO, &client_fd_set);
	FD_SET(server_fd, &client_fd_set);

    while (1)
    {
        (void)memset(buf, 0, sizeof(buf));

        /* listen from server and terminal */
        copy = client_fd_set;
        if (select(server_fd + 1, &copy, NULL, NULL, NULL) < 0)
            FATAL("select error\n");

        /* from terminal */
        if (FD_ISSET(STDIN_FILENO, &copy))
        {
            if (read(STDIN_FILENO, buf, sizeof(buf)) == 0)
            {
                message_create_close_connection(&msg_work_with_server);
                if (message_send_tls(ssl, &msg_work_with_server))
                    FATAL("Send public key error\n");
                break;
            }
            else
            {
                /* user put enter, so buf msg to sent */
                message_create_normal(&msg_private, buf);

                LOG("GOT msg from terminal: %s\n", buf);
                message_debug_print(&msg_private);
            }

        } /* from server */
        else if (FD_ISSET(server_fd, &copy))
        {
            ret = message_recv_tls(ssl, &msg_work_with_server);
            if (ret == 1)
            {
                printf("[INFO]\tConnection closed by server\n");
                break;
            }
            else if (ret)
                LOG("RECV TLS error\n");

            switch (msg_work_with_server.header.type)
            {
                /* print INFO from server */
                case MESSAGE_INFO:
                {
                    printf("[INFO]\t%s\n", msg_work_with_server.payload);
                    break;
                }
                /* print message from users */
                case MESSAGE_NORMAL:
                {
                    if (msg_work_with_server.header.payload_size > 0)
                        printf("[USER]\t%s\n", msg_work_with_server.payload);

                    break;
                }
                /* just close connestion */
                case MESSAGE_CLOSE_CONNECTION:
                {
                    printf("[INFO]\tConnection closed by server\n");
                    break;
                }
                /* got generator g from server, set into dh parameters */
                case MESSAGE_GENERATOR:
                {
                    LOG("Generator: %s\n", msg_work_with_server.payload);
                    BN_hex2bn(&dh->g, msg_work_with_server.payload);
                    have_generator = true;
                    break;
                }
                /* got p prime from server, set into dh parameters */
                case MESSAGE_PRIME:
                {
                    LOG("Prime: %s\n", msg_work_with_server.payload);
                    BN_hex2bn(&dh->p, msg_work_with_server.payload);
                    have_prime = true;
                    break;
                }
                /* update left key, position in a ring has been changed */
                case MESSAGE_LEFT_NEIGHBOR_PUBLIC_KEY:
                {
                    LOG("LPKEY: %s\n", msg_work_with_server.payload);
                    BN_hex2bn(&left_pkey, msg_work_with_server.payload);
                    break;
                }
                /* update right key, position in a ring has been changed */
                case MESSAGE_RIGHT_NEIGHBOR_PUBLIC_KEY:
                {
                    LOG("RPKEY: %s\n", msg_work_with_server.payload);
                    BN_hex2bn(&right_pkey, msg_work_with_server.payload);
                    break;
                }
                /* round ends, encrypt msg and sent to server */
                case MESSAGE_ROUND_END:
                {
                    LOG("ROUND END, send msg\n");
                    if (left_pkey == NULL || right_pkey == NULL)
                        FATAL("I CANNOT send msg\n");

                    message_create_normal(&msg_private, NULL);
                    message_encrypt(&msg_private, left_pkey, right_pkey);
                    if (message_send_tls(ssl, &msg_private))
                        FATAL("Send public key error\n");

                    message_reset(&msg_private);

                    break;
                }
                default:
                {
                    LOG("Unsupported message type\n");
                    break;
                }
            }

            /* git g and p lets rand x and compute g^x mod p */
            if (have_generator && have_prime)
            {
                DH_generate_key(dh);

                message_create_public_key(&msg_work_with_server, dh);
                LOG("PUB KEY: %s\n", msg_work_with_server.payload);

                if (message_send_tls(ssl, &msg_work_with_server))
                    FATAL("Send public key error\n");

                have_generator = false;
                have_prime = false;
            }
        }
    }

    close(server_fd);
    tls_destroy_context(ctx);
    SSL_free(ssl);
    tls_clenup();
    DH_free(dh);
}
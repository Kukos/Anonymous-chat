#ifndef MESSAGE_H
#define MESSAGE_H

/*
    Common Message structure

    Author: Michal Kukowski
    email: michalkukowski10@gmail.com

    LICENCE: GPL 3.0
*/

#include <stdint.h>
#include <stddef.h>
#include <generic.h>
#include <common.h>
#include <string.h>
#include <crc.h>
#include <log.h>
#include <inttypes.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/ssl.h>

#define MESSAGE_PAYLOAD_SIZE (2048 - sizeof(Message_header))

typedef enum message_type
{
    MESSAGE_CLOSE_CONNECTION,
    MESSAGE_ROUND_END,
    MESSAGE_INFO,
    MESSAGE_NORMAL,
    MESSAGE_CLIENT_PUBLIC_KEY,
    MESSAGE_LEFT_NEIGHBOR_PUBLIC_KEY,
    MESSAGE_RIGHT_NEIGHBOR_PUBLIC_KEY,
    MESSAGE_GENERATOR,
    MESSAGE_PRIME,
    MESSAGE_MAX_TYPE
}message_t;

typedef struct Message_header
{
    message_t type;
    uint64_t crc;
    size_t payload_size;
} Message_header;

typedef struct Message
{
    Message_header header;
    char payload[MESSAGE_PAYLOAD_SIZE];

} Message;

static ___inline___ void message_reset(Message *msg)
{
    (void)memset(msg, 0, sizeof(Message));
}

static ___inline___ void message_debug_print(Message *msg)
{
    if (msg == NULL)
        return;

    LOG("MESSAGE\n"
        "\t\ttype = %d\n"
        "\t\tcrc = %" PRIu64 "\n"
        "\t\tPsize = %zu\n"
        "\t\tPayload:%s\n",
        msg->header.type,
        msg->header.crc,
        msg->header.payload_size,
        msg->payload);
}

static ___inline___ void message_create_close_connection(Message *msg)
{
    message_reset(msg);
    msg->header.type = MESSAGE_CLOSE_CONNECTION;
}

static ___inline___ void message_create_info(Message *msg, const char *info)
{
    message_reset(msg);
    msg->header.type = MESSAGE_INFO;

    if (info != NULL)
    {
        /* write info msg */
        (void)strncpy(&msg->payload[0], info, MESSAGE_PAYLOAD_SIZE - 1);
        msg->header.payload_size = strlen(info) + 1; /* +1 NULL BYTE */
    }

    /* crc */
    msg->header.crc = crc64(&msg->payload[0], msg->header.payload_size);
}

static ___inline___ void message_create_round_end(Message *msg)
{
    message_reset(msg);
    msg->header.type = MESSAGE_ROUND_END;
}

static ___inline___ void message_create_normal(Message *msg, const char *text)
{
    /* concat with prev */
    if (msg->header.type == MESSAGE_NORMAL)
    {
        if (text != NULL)
        {
            (void)strncat(&msg->payload[0], text, MESSAGE_PAYLOAD_SIZE - 1);
            msg->header.payload_size += strlen(text); /* size contains NULL byte, so without +1 */
        }
    }
    else
    {
        message_reset(msg);
        msg->header.type = MESSAGE_NORMAL;

        /* write msg */
        if (text != NULL)
        {
            (void)strncpy(&msg->payload[0], text, MESSAGE_PAYLOAD_SIZE - 1 - msg->header.payload_size);
            msg->header.payload_size = strlen(text) + 1; /* +1 NULL BYTE */
        }
    }

    /* crc */
    msg->header.crc = crc64(&msg->payload[0], msg->header.payload_size);
}

static ___inline___ void message_create_public_key(Message *msg, const DH *key)
{
    message_reset(msg);
    msg->header.type = MESSAGE_CLIENT_PUBLIC_KEY;

    (void)strncpy(&msg->payload[0], BN_bn2hex(key->pub_key), MESSAGE_PAYLOAD_SIZE - 1);
    msg->header.payload_size = strlen(&msg->payload[0]);

    msg->header.crc = crc64(&msg->payload[0], msg->header.payload_size);
}

static ___inline___ void message_create_left_neighbor_public_key(Message *msg, const BIGNUM *key)
{
    message_reset(msg);
    msg->header.type = MESSAGE_LEFT_NEIGHBOR_PUBLIC_KEY;

    (void)strncpy(&msg->payload[0], BN_bn2hex(key), MESSAGE_PAYLOAD_SIZE - 1);
    msg->header.payload_size = strlen(&msg->payload[0]);

    msg->header.crc = crc64(&msg->payload[0], msg->header.payload_size);
}

static ___inline___ void message_create_right_neighbor_public_key(Message *msg, const BIGNUM *key)
{
    message_reset(msg);
    msg->header.type = MESSAGE_RIGHT_NEIGHBOR_PUBLIC_KEY;

    (void)strncpy(&msg->payload[0], BN_bn2hex(key), MESSAGE_PAYLOAD_SIZE - 1);
    msg->header.payload_size = strlen(&msg->payload[0]);

    msg->header.crc = crc64(&msg->payload[0], msg->header.payload_size);
}

static ___inline___ void message_create_generator(Message *msg, const DH *key)
{
    message_reset(msg);
    msg->header.type = MESSAGE_GENERATOR;

    (void)strncpy(&msg->payload[0], BN_bn2hex(key->g), MESSAGE_PAYLOAD_SIZE - 1);
    msg->header.payload_size = strlen(&msg->payload[0]);

    msg->header.crc = crc64(&msg->payload[0], msg->header.payload_size);
}

static ___inline___ void message_create_prime(Message *msg, const DH *key)
{
    message_reset(msg);
    msg->header.type = MESSAGE_PRIME;

    (void)strncpy(&msg->payload[0], BN_bn2hex(key->p), MESSAGE_PAYLOAD_SIZE - 1);
    msg->header.payload_size = strlen(&msg->payload[0]);

    msg->header.crc = crc64(&msg->payload[0], msg->header.payload_size);
}

static ___inline___ int message_check_correctness(const Message *msg)
{
    if (msg->header.type >= MESSAGE_MAX_TYPE)
        return -1;

    if (msg->header.payload_size == 0)
        return 0;

    return !(crc64(&msg->payload[0], msg->header.payload_size) == msg->header.crc);
}

static ___inline___ int message_send_tls(SSL *ssl, Message *msg)
{
    int bytes;

    bytes = SSL_write(ssl, (const void *)msg, sizeof(Message));
    if ((size_t)bytes < sizeof(Message))
        ERROR("SSL_write error\n", 1);

    return 0;
}

static ___inline___ int message_recv_tls(SSL *ssl, Message *msg)
{
    int bytes;

    bytes = SSL_read(ssl, (void *)msg, sizeof(Message));
    if (bytes == 0)
        return 1;

    if ((size_t)bytes < sizeof(Message))
        ERROR("SSL_read error\n", 2);

    if (message_check_correctness(msg))
        ERROR("Message is corrupted\n", 3);

    message_debug_print(msg);

    return 0;
}

#endif
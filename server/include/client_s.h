#ifndef CLIENT_S_H
#define CLIENT_S_H

/*
    Implementation of client structure for server

    Author: Michal Kukowski
    email: michalkukowski10@gmail.com

    LICENCE: GPL3.0
*/

#include <openssl/bn.h>
#include <message.h>
#include <list2d.h>

typedef struct Client
{
    int fd;
    SSL *ssl_session;
    BIGNUM *pkey;
    Message msg;

} Client;

/*
    Create new client

    PARAMS
    @IN fd - fd
    @IN session - tls session

    RETURN
    NULL iff failure
    Pointer to new client iff success
*/
Client *client_create(int fd, SSL *session);

/*
    Destroy client

    PARAMS
    @IN client - pointer to client

    RETURN
    This is a void function
*/
void client_destroy(Client *client);

/*
    Create List2D for clients

    PARAMS
    NO PARAMS

    RETURN
    NULL iff failure
    Pointer to new List2D iff success
*/
List2D *create_client_list2d(void);

#endif
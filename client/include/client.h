#ifndef CLIENT_H
#define CLIENT_H

/*
    Simple TLS Client for anonymus chat

    Author: Michal Kukowski
    email: michalkukowski10@gmail.com

    LICENCE: GPL3.0
*/

/*
    MAIN client JOB

    PARAMS
    @IN host_name - host name
    @IN port - port

    RETURN
    This is a void function
*/
void client_job(const char *host_name, int port);

#endif
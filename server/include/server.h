#ifndef SERVER_H
#define SERVER_H

/*
    Simple TLS server for anonymus chat

    Author: Michal Kukowski
    email: michalkukowski10@gmail.com

    LICENCE: GPL3.0
*/

/*
    MAIN server JOB

    PARAMS
    @IN host_name - host name
    @IN port - port

    RETURN
    This is a void function
*/
void server_job(const char *host_name, int port);

#endif
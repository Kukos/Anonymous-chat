#include <socket_lib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <log.h>
#include <stdbool.h>
#include <log.h>

int tcp_create_socket(const char *host_name, int port)
{
	struct sockaddr_in sn = {0};
	int s;
	struct hostent *he;

	TRACE();

    he = gethostbyname(host_name);
    if (he == NULL)
        ERROR("gethostbyname error\n", -1);

	sn.sin_family = AF_INET;
	sn.sin_port = htons((unsigned short)port);
	sn.sin_addr = *(struct in_addr *)(he->h_addr_list[0]);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == -1)
        ERROR("socker create error\n", -1);

	LOG("Socket %d created\n", s);

	if (bind(s, (struct sockaddr *)&sn, sizeof(sn)) == -1)
        ERROR("socket bind error\n", -1);

	LOG("Socket %d binded\n", s);

	return s;
}

int tcp_request_connection(const char *host_name, int port)
{
	struct sockaddr_in sn;
	int s;
	bool success;
	struct hostent *he;

	TRACE();

	he = gethostbyname(host_name);
    if (he == NULL)
        ERROR("gethostbyname error\n", -1);

	sn.sin_family = AF_INET;
	sn.sin_port = htons((unsigned short)port);
	sn.sin_addr = *(struct in_addr *)(he->h_addr_list[0]);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == -1)
    	ERROR("socker create error\n", -1);

	LOG("Socket %d created\n", s);

	success = false;
	while (!success)
	{

		success = connect(s, (struct sockaddr *)&sn, sizeof(sn)) != -1;
		if (!success)
			sleep(1);

		LOG("Connection status: %d\n", success);
	}
	return s;
}

int tcp_accept_connection(int s)
{
	struct sockaddr_in sn;
	socklen_t l = sizeof(sn);
	int fd;

	TRACE();

	LOG("Socket %d is listening\n", s);
	sn.sin_family = AF_INET;
	if (listen(s, 1) == -1)
		ERROR("listen socket error\n", -1);

	fd = accept(s, (struct sockaddr *)&sn, (socklen_t *)&l);
	if (fd == -1)
		ERROR("accept tcp error\n", -1);

	LOG("Connection from %d socket, accepted on %d fd\n", s, fd);

	return fd;
}
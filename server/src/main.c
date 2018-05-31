#include <stdio.h>
#include <server.h>
#include <stdlib.h>
#include <log.h>
#include <common.h>

___before_main___(1) void init(void);
___after_main___(1) void deinit(void);

___before_main___(1) void init(void)
{
    (void)log_init(stdout, NO_LOG_TO_FILE);
}

___after_main___(1) void deinit(void)
{
    log_deinit();
}

int main(int argc, char **argv)
{
    char *host_name;
    int port;

    if (argc < 3)
    {
        printf("Need host_name and port\n");
        return 1;
    }

    host_name = argv[1];
    port = atoi(argv[2]);

    if (port < 5000)
    {
        printf("Please use port >= 5000\n");
        return 1;
    }

    server_job(host_name, port);

    return 0;
}
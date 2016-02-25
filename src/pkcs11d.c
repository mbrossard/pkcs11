/*
 * Copyright (C) 2016 Mathias Brossard <mathias@brossard.org>
 */

#include "network.h"
int main(int argc, char **argv)
{
    struct sockaddr_un sockaddr;
    int fd;
    fd = nw_unix_server("pkcs11d.sock", &sockaddr, 0, 0, 0, 64);
    close(fd);
    fd = nw_tcp_server(1234, 0, 64);
    
    do {
        struct sockaddr address;
        socklen_t a_len = sizeof(address);
        int s = accept(fd, &address, &a_len);

        nw_nwrite(s, "Hello world!\n", 14);
        close(s);
    } while(1);

    close(fd);
}

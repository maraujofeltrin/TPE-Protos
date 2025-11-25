#ifndef SOCKS5_H_
#define SOCKS5_H_

#include "selector.h"
#include "stm.h"
#include "parser.h"
#include "handshake.h"
#include "buffer.h"
#include "authentication.h"
#include <pthread.h>


#define SOCKS5_VERSION 0x05

//VER SI FALTAN MAS
typedef enum {
    HANDSHAKE,
    HANDSHAKE_RESPONSE,
    REQUEST,
    REQUEST_RESPONSE,
    ERROR,
    CLOSED,
    REQUEST_CONNECT,
    REQUEST_BIND,
    AUTHENTICATION,
    AUTHENTICATION_RESPONSE
} socks5_state_t;


typedef struct socks5_connection {
    int client_fd;
    int target_fd;
    socks5_state_t state;
    void *data;
    char target_addr[512];
    char client_ip[64];
    struct state_machine stm;
    union{
        handshake_context_t handshake;
        handshake_parser_t request;
        authentication_context_t authentication;
    }parser;
    buffer read_c, write_c;
    buffer read_p, write_p;
    int remote_domain;
    socklen_t remote_address_len;
    struct sockaddr_storage remote_address;

    struct addrinfo * req_address;
    struct addrinfo * cur_req_address;

} socks5_connection_t;




#endif
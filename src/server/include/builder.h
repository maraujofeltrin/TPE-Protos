#ifndef PARSER_H
#define PARSER_H
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

/// Definición de tipos de dirección SOCKS5
typedef enum {
    SOCKS5_ATYP_IPV4       = 0x01,
    SOCKS5_ATYP_DOMAINNAME = 0x03,
    SOCKS5_ATYP_IPV6       = 0x04
} socks5_address_type;

/// Definición de comandos SOCKS5
typedef enum {
    SOCKS5_COM_CONNECT       = 0x01,
    SOCKS5_COM_BIND          = 0x02,
    SOCKS5_COM_UDP_ASSOCIATE = 0x03
} socks5_command;

typedef enum {
    SOCKS5_REP_SUCCEEDED              = 0x00,
    SOCKS5_REP_GENERAL_FAILURE        = 0x01,
    SOCKS5_REP_CONNECTION_NOT_ALLOWED = 0x02,
    SOCKS5_REP_NETWORK_UNREACHABLE    = 0x03,
    SOCKS5_REP_HOST_UNREACHABLE       = 0x04,
    SOCKS5_REP_CONNECTION_REFUSED     = 0x05,
    SOCKS5_REP_TTL_EXPIRED            = 0x06,
    SOCKS5_REP_COMMAND_NOT_SUPPORTED  = 0x07,
    SOCKS5_REP_ADDRESS_TYPE_NOT_SUPPORTED = 0x08
} socks5_response_type;

typedef struct {
    socks5_address_type atyp;
    union {
        uint8_t  ipv4[4];
        struct {
            uint8_t  length;
            char     addr[255];
        } domainname;
        uint8_t  ipv6[16];
    } address;
    uint16_t port;
} socks5_address;

typedef struct socks5_request_parser{
    socks5_command command;
    socks5_address dest_address;
    uint8_t reserved;
    uint8_t version;
} socks5_request_parser_t;

typedef struct socks5_response_parser{
    uint8_t version;
    uint8_t reserved;
    socks5_address add;
    socks5_response_type response;
} socks5_response_parser_t;

typedef struct handshake_parser{
    socks5_response_parser_t response;
    socks5_request_parser_t request;
} handshake_parser_t;


int parse_socks5_request(socks5_request_parser_t * request, const uint8_t * buf, size_t len, size_t * parsed_bytes);
int socks5_response(socks5_response_parser_t * response, uint8_t ** out_buf, size_t * out_len);

#endif





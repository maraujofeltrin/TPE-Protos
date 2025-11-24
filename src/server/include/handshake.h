#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include <stdint.h>
#include <stdlib.h>

#define NO_AUTH 0x00
#define AUTH_USER 0x02
#define HANDSHAKE_METHOD_NO_ACCEPTABLE 0xFF

typedef struct handshake_request {
    uint8_t version;
    uint8_t nmethods;
    uint8_t * methods; //VER SI ES ESTATICO 
} handshake_request_t;

typedef struct handshake_response {
    uint8_t version;
    uint8_t method;
} handshake_response_t;

typedef struct handshake_context {
    handshake_request_t request;
    handshake_response_t response;
    size_t bytes_read;
    size_t bytes_written;
} handshake_context_t;


#endif